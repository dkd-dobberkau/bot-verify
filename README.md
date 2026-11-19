# bot-verify

Answers one question for website operators: **is this request really from the
bot it claims to be?**

A User-Agent string is free text. Anyone can call themselves GPTBot or
Googlebot. Most bot operators publish how to check the claim (an IP list or a
reverse-DNS suffix), but every operator does it differently, in a different
place and format. bot-verify collects those published methods and answers the
question for a given IP and bot name, over an HTTP API or, for webservers and
WAFs, as a DNS zone (`bot-verify-dns`, see [DNS verify zone](#dns-verify-zone)).

It uses only what operators publish about their own bots. It stores no visitor
data and logs no queried IPs.

Status: v0.2.0.

| Document | |
|---|---|
| [docs/idea.md](docs/idea.md) | Background and design decisions |
| [docs/verdicts.md](docs/verdicts.md) | How an answer is reached, limits and timeouts |
| [docs/bots.md](docs/bots.md) | Why each bot is classified the way it is |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup, adding bots, code rules |
| [SECURITY.md](SECURITY.md) | Reporting issues, known limitations |

Spun off from [goodbot-badbot.com](https://goodbot-badbot.com), which measures
robots.txt compliance and keeps a catalog of what operators say about their bots
(https://goodbot-badbot.com/bots).

## Answers

| `result`        | Meaning |
|-----------------|---------|
| `confirmed`     | The IP is in the operator's published list (`method: ip_list`), or its reverse-DNS name is under the operator's domain and resolves back to the same IP (`method: rdns`). |
| `refuted`       | The operator's lists are loaded and the IP is not in them, and the reverse-DNS check (if the operator offers one) gave a definite no. |
| `not_checkable` | The operator publishes nothing to check against, or DNS did not answer, or the lists have not loaded yet. `reason` says which. Never treat this as refuted. |

`sources` lists the operator URLs each answer rests on; `data_age_seconds` is
how old the IP list behind it is.

## Taking the client IP

A verify answer is only as good as the IP you ask about, and a "confirmed" for
a forged IP is worse than no answer.

- Use the address of the TCP peer, or the address set by the one reverse proxy
  you control.
- Never take the left-most `X-Forwarded-For` entry; the client writes that.
- With uvicorn, `--forwarded-allow-ips` must list only your proxy, never `"*"`.
  With nginx, set `set_real_ip_from` to your proxy's address only.

## Run

```sh
go build -o bot-verify ./cmd/bot-verify
./bot-verify -listen :8080 -bots bots.yaml
```

| Flag                | Default     | |
|---------------------|-------------|-|
| `-listen`           | `:8080`     | HTTP listen address |
| `-bots`             | `bots.yaml` | Bot catalog |
| `-refresh`          | `6h`        | Interval between refreshes of the operator lists (sent with `If-None-Match`/`If-Modified-Since`; a failed fetch keeps the last good copy) |
| `-snapshot`         |             | JSONL file the lists are kept in, so a restart is ready at once; off when unset (see below) |
| `-rdns-ttl`         | `15m`       | Cache lifetime of reverse-DNS answers (failures are not cached) |
| `-rdns-concurrency` | `64`        | Maximum concurrent reverse-DNS checks |
| `-rate-limit`       | `10`        | Requests per second to `/v1/` per client IPv4 /24 or IPv6 /56; `0` turns it off (see below) |
| `-rate-burst`       | `40`        | Burst size of `-rate-limit` |
| `-trusted-proxy`    |             | Comma-separated networks of your reverse proxies, repeatable; only a peer inside them may name the client in `X-Forwarded-For` |
| `-probe`            |             | Check `/healthz` at `-listen` and exit; used as container health check |
| `-version`          |             | Print the version |

Docker:

```sh
docker build --build-arg VERSION=0.2.0 -t bot-verify .
docker run --rm -p 8080:8080 bot-verify
```

**Rate limit.** Each uncached reverse-DNS check costs up to three DNS queries,
so `/v1/` is limited per client network (IPv4 /24, IPv6 /56, as in the DNS
zone). Over the limit the answer is `429` with error code `rate_limited` and
`Retry-After: 1`. `/healthz` and `/readyz` are not limited. A full limiter
table (100,000 networks) evicts only idle entries and refuses new networks
until then.

The client is the TCP peer. Behind a reverse proxy, every request comes from
the proxy and all clients would share one bucket: set `-trusted-proxy` to the
proxy's network. Then `X-Forwarded-For` is read from the right, past further
trusted hops; the first other address is the client, and entries left of it,
which the client wrote, are never used. On Mittwald container hosting the
ingress connects from `100.64.0.0/10` (RFC 6598). Never trust a network that
untrusted clients can connect from.

**Maximum list age.** A list whose last successful fetch (or 304) is older
than 7 days counts as not loaded: it neither confirms nor refutes, and
`/v1/verify` answers `not_checkable` with reason `source data stale`.

**Snapshot.** With `-snapshot /data/lists.jsonl`, the lists are written to that
file after every refresh cycle that changed them (temp file and rename, mode
0600) and read back at start, before the first fetch. Each line is checked
like a fresh fetch; lines that are malformed, older than 7 days or for a source
no longer in `bots.yaml` are dropped with a warning. The first refresh still
runs at once and fetches every list in full: ETag and Last-Modified are not
restored from the file, so a 304 can only confirm lists this process fetched
itself. Until that refresh, the file decides verdicts, so keep it writable by
the service only. In Docker, mount a volume writable by the nonroot user
(UID 65532) for the file.

## API

All endpoints are `GET` and return `application/json; charset=utf-8`.

### `GET /v1/verify?ip=<address>&bot=<id>`

```sh
curl 'localhost:8080/v1/verify?ip=66.249.66.1&bot=googlebot'
```
```json
{"ip":"66.249.66.1","bot":"googlebot","result":"confirmed","method":"ip_list",
 "sources":["https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
            "https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests"],
 "data_age_seconds":1}
```

```sh
curl 'localhost:8080/v1/verify?ip=213.180.203.1&bot=yandexbot'
```
```json
{"ip":"213.180.203.1","bot":"yandexbot","result":"confirmed","method":"rdns",
 "hostname":"213-180-203-1.spider.yandex.com","sources":["https://yandex.com/support/webmaster/en/robot-workings/check-yandex-robots.html"]}
```

Errors: `400 {"error":{"code":"invalid_ip"|"invalid_bot",...}}`,
`404 {"error":{"code":"unknown_bot",...}}`.

### `GET /v1/bots`

Every bot with `id`, `name`, `ua_tokens`, `checkable`, `methods`
(`ip_list`, `rdns`) and `docs`.

### `GET /v1/dataset`

The normalised dataset: per bot its reverse-DNS suffixes, its `not_checkable`
reason, or its sources with `fetched_at` and all prefixes.

### `GET /healthz`

Liveness, always 200 while the process serves requests; the container health
check uses it.

`{"status":"ok","sources_loaded":18,"sources_total":18}`

### `GET /readyz`

Readiness for load balancers: 200 `"ready"` as soon as one IP list is loaded
and fresh, which a snapshot gives before the first fetch. Otherwise 503 with
`"status":"starting"` until the first refresh cycle has finished, and 503
`"no_sources_loaded"` after it. Until then, bots checked only by IP list get
`not_checkable`.

`{"status":"ready","sources_loaded":18,"sources_total":18}`

## DNS verify zone

`bot-verify-dns` is a separate binary that answers the same question over DNS,
for webservers and WAFs that can do a DNS lookup per request but have no HTTP
client. It fetches the operator lists itself (same fetch protections as the
API), never sends DNS queries of its own, and checks IP lists only.

```sh
go build -o bot-verify-dns ./cmd/bot-verify-dns
./bot-verify-dns -zone verify.example -ns ns1.verify.example=192.0.2.53 \
  -hostmaster hostmaster.verify.example -snapshot /data/dns-lists.jsonl
dig @127.0.0.1 -p 5353 1.216.73.216.claudebot.verify.example A
```

Query name: `<reversed address>.<bot-id>.<zone>`. IPv4 is reversed by octet
(`1.66.249.66.gptbot.verify.example` for 66.249.66.1), IPv6 by nibble as in
`ip6.arpa` (32 labels). IPv4-mapped IPv6 is treated as IPv4.

| Case | Answer |
|---|---|
| The address is in a loaded, fresh list of the bot | NOERROR, `A 127.0.0.2` (TTL 300) |
| The bot has IP lists only, all are loaded and fresh, none holds the address | NXDOMAIN (refuted) |
| A list is not loaded or older than 7 days | NODATA (not checkable) |
| The bot also has reverse-DNS rules, `not_checkable`, rDNS rules only, or is unknown | NODATA |
| A name above an address (`gptbot.<zone>`, `66.gptbot.<zone>`) | NODATA |
| An IPv4 name of four single digits (`1.0.0.2.gptbot.<zone>`), which is also an IPv6 prefix | never NXDOMAIN, so NODATA when the list misses |
| A label that cannot be part of an address | NXDOMAIN |
| Outside the zone, or not class IN | REFUSED |

NXDOMAIN and NODATA carry the zone SOA; its minimum (300 s) is how long
resolvers cache them. Only 8 bots can be refuted today: gptbot, chatgpt-user,
oai-searchbot, claudebot, claude-user, shapbot, perplexitybot, duckduckbot.

| Flag | Default | |
|---|---|---|
| `-listen` | `:5353` | UDP and TCP address |
| `-bots` | `bots.yaml` | Bot catalog |
| `-zone` | required | Zone name |
| `-ns` | required | Name server, repeatable: `name`, or `name=ip[,ip]`. A name inside the zone needs its addresses (the zone serves them), must not be the apex, and its label next to the zone must not be a bot id |
| `-hostmaster` | required | SOA mailbox as a domain name |
| `-refresh` | `6h` | Interval between list refreshes |
| `-snapshot` | | JSONL snapshot, as for the API |
| `-tcp-max-conns` | `512` | Concurrent TCP connections in total |
| `-tcp-max-per-source` | `16` | Concurrent TCP connections per IPv4 address or IPv6 /56 |
| `-probe` | | Query the server at `-listen` and exit (container health check); with `-zone`, it requires the zone SOA |
| `-version` | | Print the version |

Per source network (IPv4 /24 or IPv6 /56, as in response rate limiting of
other authoritative servers), UDP queries above 200/s (burst 400) get an
empty reply with the TC bit, so resolvers retry over TCP. TCP has no query
rate limit but a connection cap (`-tcp-max-conns`, `-tcp-max-per-source`), a
2 s idle timeout and at most 32 queries per connection. Replies are always
compressed, and opcodes other than QUERY get NOTIMP. Logs hold aggregate
answer counts only, never names or clients.

Docker (nonroot cannot bind port 53, so map it):

```sh
docker build --target dns -t bot-verify-dns .
docker run --rm -p 53:5353/udp -p 53:5353/tcp bot-verify-dns \
  -zone verify.example -ns ns1.verify.example=192.0.2.53 -hostmaster hostmaster.verify.example
```

The zone can be delegated publicly from its parent, or served only to your
own resolver. Unbound as a stub zone:

```
server:
    do-not-query-localhost: no
    domain-insecure: "verify.example"
stub-zone:
    name: "verify.example"
    stub-addr: 127.0.0.1@5353
```

**Allow confirmed bots** with any DNSBL client, which sees only "resolves" or
"does not resolve". ModSecurity, skipping the challenge for a real GPTBot:

```
SecRule REQUEST_HEADERS:User-Agent "@contains GPTBot" "id:1000100,phase:1,pass,nolog,chain"
    SecRule REMOTE_ADDR "@rbl gptbot.verify.example" "setvar:tx.verified_bot=1"
```

Then let the challenge rule skip requests with `tx.verified_bot=1`.

**Block spoofers** only with a client that sees the RCODE, and only on
NXDOMAIN. NODATA and lookup failures mean "cannot tell": pass or challenge.
OpenResty, with a caching resolver (such as the Unbound above) at 127.0.0.1:

```lua
-- access_by_lua_block
local resolver = require "resty.dns.resolver"
local ua = ngx.var.http_user_agent or ""
local a, b, c, d = ngx.var.remote_addr:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
if a and ua:find("GPTBot", 1, true) then
    local r = resolver:new{ nameservers = { "127.0.0.1" }, timeout = 500 }
    local answers = r and r:query(d .. "." .. c .. "." .. b .. "." .. a .. ".gptbot.verify.example", { qtype = r.TYPE_A })
    if answers and answers.errcode == 3 then -- NXDOMAIN: the list refutes it
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end
```

## Adding a bot

Add an entry to `bots.yaml`, with the operator's documentation as `docs`:

```yaml
  - id: examplebot                     # [a-z0-9-], unique
    name: ExampleBot
    ua_tokens: [ExampleBot]
    ip_sources:                        # published lists, https only
      - url: https://example.com/examplebot.json
        format: google-prefixes        # {"prefixes":[{"ipv4Prefix":…}]}, or cidr-lines
    rdns_suffixes: [crawl.example.com] # forward-confirmed reverse DNS
    docs: https://example.com/bot
```

A bot without either gets `not_checkable: "<the operator's own statement>"`
instead. Only list a reverse-DNS suffix if nobody but the operator can get
names under it: `googleusercontent.com`, for example, is any Google Cloud
customer's, so it is not a Googlebot suffix.

`go test ./...` checks the file. Read [docs/bots.md](docs/bots.md) before
changing an entry.

## License

MIT, see [LICENSE](LICENSE).
