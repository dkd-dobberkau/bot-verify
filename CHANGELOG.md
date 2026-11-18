# Changelog

## Unreleased

- New `bot-verify-dns` binary and `dns` image target: an authoritative DNS
  zone `<reversed address>.<bot-id>.<zone>` answering `A 127.0.0.2` for
  confirmed, NXDOMAIN for refuted and NODATA for not checkable, with SOA/NS,
  optional in-zone glue, REFUSED outside the zone, and per-source rate
  limiting by truncation. Adds the dependency `github.com/miekg/dns`.
- Lists older than 7 days count as not loaded: `/v1/verify` gives
  `not_checkable` with reason `source data stale`, and `/readyz` and
  `/healthz` count fresh lists only.
- `-snapshot <path>` on both binaries keeps the lists in a JSONL file for a
  warm start; `/readyz` is ready as soon as one fresh list is loaded.
  Temp files a crash left behind are removed at start, and the directory
  is synced after each write so a power loss cannot bring back an older file.

- Fix: a transient A-record failure during forward confirmation was reported
  as "not found" by the merged A+AAAA lookup and became a cached `refuted` for
  a real crawler. The forward lookup now asks only for the queried IP's family.
- Fix: operator lists were accepted after an `https://` source redirected to
  plain `http://`, so plaintext content could confirm spoofed IPs. Such
  redirects are now refused.
- The list fetcher refuses connections to non-public addresses (loopback,
  private, link-local, CGNAT), so a listed origin cannot point it at internal
  endpoints by redirect or DNS. Skipped when an outbound proxy is configured.
- Tests pin how the PTR step classifies resolver failures: only "no PTR
  exists" can refute; SERVFAIL, lame referral, truncation, malformed records
  and timeouts give not_checkable.
- CI: actions/checkout and actions/setup-go pinned by commit SHA.
- IPv4-mapped prefixes in operator lists are treated as IPv4, so the IPv4
  breadth limit applies and they match the queried addresses.
- A source may list at most 50,000 prefixes; /v1/dataset is served from a
  cache rebuilt only when a list changes.
- Request headers are capped at 8 KiB.
- New /readyz: 503 until the first refresh cycle and while no list is loaded.
- Concurrent checks of the same IP and bot share one reverse-DNS lookup.
- Base images pinned by digest; Dependabot keeps digests, action SHAs and Go
  modules current.
- Docs: verdict logic (`docs/verdicts.md`), per-bot rationale (`docs/bots.md`),
  CONTRIBUTING.md, SECURITY.md.
- Module path `github.com/dkd-dobberkau/bot-verify`; GitHub Actions CI with
  tests and Trivy scan.

## 0.1.0 – 2026-11-18

- First version: single Go binary with HTTP API (`/v1/verify`, `/v1/bots`,
  `/v1/dataset`, `/healthz`).
- `bots.yaml` with 51 bots derived from goodbot-badbot's bot catalog; 27 can be
  checked by published IP list and/or forward-confirmed reverse DNS.
- Operator lists refreshed every 6 hours with conditional requests; the last
  good copy survives failed fetches.
- Dockerfile (distroless, non-root, health check via `-probe`).
