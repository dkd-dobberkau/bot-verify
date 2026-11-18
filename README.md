# bot-verify

Answers one question for website operators: **is this request really from the
bot it claims to be?**

A User-Agent string is free text. Anyone can call themselves GPTBot or
Googlebot. Most bot operators publish how to check the claim (an IP list or a
reverse-DNS suffix), but every operator does it differently, in a different
place and format. bot-verify collects those published methods and answers the
question for a given IP and bot name.

It uses only what operators publish about their own bots. It stores no visitor
data and logs no queried IPs.

Status: v0.1.0.

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
| `-rdns-ttl`         | `15m`       | Cache lifetime of reverse-DNS answers (failures are not cached) |
| `-rdns-concurrency` | `64`        | Maximum concurrent reverse-DNS checks |
| `-probe`            |             | Check `/healthz` at `-listen` and exit; used as container health check |
| `-version`          |             | Print the version |

Docker:

```sh
docker build --build-arg VERSION=0.1.0 -t bot-verify .
docker run --rm -p 8080:8080 bot-verify
```

A public instance belongs behind a reverse proxy with per-client rate limiting;
each uncached reverse-DNS check costs up to three DNS queries.

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

Readiness for load balancers: 503 with `"status":"starting"` until the first
refresh cycle has finished, and 503 `"no_sources_loaded"` if no IP list could
be loaded. Until then, bots checked only by IP list get `not_checkable`.

`{"status":"ready","sources_loaded":18,"sources_total":18}`

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
