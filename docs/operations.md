# Operations

How the public instance at https://verify.goodbot-badbot.com runs. Mittwald
project and stack IDs are kept in `.deploy.env`, not here.

## Hosting

- **Mittwald container hosting**, in the same project as goodbot-badbot.com
  but in a stack of its own (`bot-verify`). `mw stack deploy` replaces a whole
  stack, so the two projects deploy independently.
- **One service**, `bot-verify`, from `docker-compose.mittwald.yml`, image
  `ghcr.io/dkd-dobberkau/bot-verify:<tag>` (built for `linux/amd64`; Mittwald
  has no ARM). The project's registry entry for `ghcr.io` holds the pull
  credentials.
- **Volume** `lists` at `/data` keeps the snapshot (`-snapshot
  /data/lists.jsonl`), so a restart answers at once instead of after the first
  refresh.
- **Virtual host** `verify.goodbot-badbot.com` routes `/` to the container's
  port 8080. It points at the container ID, which survives a recreate; it
  changes only if the stack is deleted and created again, and then the
  virtual host must be updated (`mw domain virtualhost update`).
- **DNS** for goodbot-badbot.com is managed by Mittwald; creating the virtual
  host created the A and AAAA records.
- **Client IP:** the ingress connects from `100.64.0.0/10` and appends the
  client to `X-Forwarded-For`, so the stack runs with `-trusted-proxy
  100.64.0.0/10`. Without it every client would share the ingress's
  rate-limit bucket. Trusting the whole range is safe only while no client
  reaches the ingress from inside it: `clientAddr` skips trusted entries, so
  such a client could name its own bucket. Checked 2026-11-19 with 45
  requests to `/v1/bots`, each with a different made-up `X-Forwarded-For`,
  from outside and from goodbot-badbot's container: both were limited after
  about 40, the same as without the header, so the ingress appends the real
  sender and goodbot-badbot does not arrive from 100.64.0.0/10. Whether other
  Mittwald customers' workloads can arrive from that range is Mittwald's
  routing and is not checked; if it changes, narrow `-trusted-proxy`.
- **Other stacks cannot reach the container.** Its service name does not
  resolve there, and connections to its address time out (seen 2026-11-19).
  goodbot-badbot calls the public URL.
- **The DNS zone (`bot-verify-dns`) is not hosted.** Mittwald exposes only TCP
  ports; an authoritative server needs UDP 53.

## Deploy

```sh
cp .deploy.env.example .deploy.env   # once: STACK_ID, PROJECT_ID
./deploy.sh            # tag <short-sha>, "-dirty" with uncommitted changes
./deploy.sh v0.3.0     # a release tag
```

`deploy.sh` builds and pushes the image, runs `mw stack deploy`, waits until
the container logs `"msg":"starting"` with the new version (Mittwald's
reported image can be stale), recreates the container only if that does not
happen, and finally checks `https://verify.goodbot-badbot.com/healthz`.

**Rollback:** `./deploy.sh <older tag>` rebuilds that tag from the working
tree, so check it out first (`git switch --detach <tag>`).

## Certificates

Let's Encrypt via the ingress (`tls.acme`). For a new virtual host the
certificate did not come on its own: the ingress showed `isCreated: false`
for an hour, with DNS and ownership fine, and served the ingress
controller's fake certificate. It was issued 4.5 minutes after

```sh
curl -X POST -H "Authorization: Bearer $(cat ~/.config/mw/token)" \
  https://api.mittwald.de/v2/ingresses/<ingress-id>/actions/request-acme-certificate-issuance
```

`mw domain virtualhost get <id> -o json` shows `tls.isCreated` and the
request deadline.

## Monitoring

With the existing dkd monitoring, check:

| Check | Expect | Means when it fails |
|---|---|---|
| `GET https://verify.goodbot-badbot.com/readyz` | 200, body contains `"status":"ready"` | Down, or no fresh list loaded (503 `starting` / `no_sources_loaded`) |
| `GET https://verify.goodbot-badbot.com/healthz` | 200 | Process or ingress down |
| TLS certificate of `verify.goodbot-badbot.com` | more than 14 days left | Renewal failed; see Certificates |
| `GET /healthz`, field `sources_loaded` = `sources_total` | equal | An operator list failed to refresh for a while; see the logs |

`/readyz` and `/healthz` are not rate-limited, so a short check interval is
fine. A list older than 7 days counts as not loaded; `/v1/verify` then
answers `not_checkable` with reason `source data stale`.

## Logs and state

```sh
mw container list --project-id <project>
mw container logs <container> --project-id <project> --no-pager
```

The log is JSON: `starting` with the version, `snapshot loaded`, `sources
refreshed` with the number of failed sources, `source refresh failed` per
failure, and one `request` line per request (method, path, status, duration;
never query strings or client addresses). The image has no shell, so
`mw container exec` does not work; `mw container port-forward <container>
8080` reaches the API directly.

## Limits

Defaults: 10 requests per second to `/v1/` per IPv4 /24 or IPv6 /56, burst 40
(`-rate-limit`, `-rate-burst` in the compose `command`). Over the limit:
429 `rate_limited`. All of goodbot-badbot's calls come from one address, so
they share one bucket. The ingress sees them from an address outside
100.64.0.0/10 (checked 2026-11-19, see Hosting).
