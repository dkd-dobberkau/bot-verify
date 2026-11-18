# Changelog

## 0.2.0 – 2026-11-19

### Added

- `bot-verify-dns` binary and `dns` image target: an authoritative DNS zone
  `<reversed address>.<bot-id>.<zone>` answering `A 127.0.0.2` for confirmed,
  NXDOMAIN for refuted and NODATA for not checkable, with SOA/NS, optional
  in-zone glue, REFUSED outside the zone, NOTIMP for opcodes other than
  QUERY, compressed replies, and rate limiting:
  - UDP per IPv4 /24 and IPv6 /56 (200/s, burst 400), answered with empty
    truncated replies over the limit; a full limiter table evicts idle
    entries;
  - TCP connections capped by `-tcp-max-conns` (512) and
    `-tcp-max-per-source` (16), with a 2 s idle timeout and 32 queries per
    connection.

  Adds the dependency `github.com/miekg/dns`.
- `-snapshot <path>` on both binaries keeps the lists in a JSONL file for a
  warm start. Lines are checked like a fresh fetch, written atomically
  (temp file, rename, directory sync), and leftover temp files are removed
  at start. ETag and Last-Modified are not restored, so the first refresh
  after a start fetches every list in full.
- `GET /readyz`: ready once one fresh list is loaded (a snapshot gives that
  before the first fetch); 503 `starting` before the first refresh cycle and
  503 `no_sources_loaded` after it.
- Docs: verdict logic (`docs/verdicts.md`), per-bot rationale
  (`docs/bots.md`), CONTRIBUTING.md, SECURITY.md, and a DNS section in the
  README with Unbound, ModSecurity and OpenResty examples.

### Changed

- Lists older than 7 days count as not loaded: `/v1/verify` gives
  `not_checkable` with reason `source data stale`, and `/readyz` and
  `/healthz` count fresh lists only.
- A source may list at most 50,000 prefixes; IPv4-mapped prefixes are
  treated as IPv4, so the IPv4 breadth limit applies.
- `/v1/dataset` is served from a cache rebuilt only when a list changes.
- Request headers are capped at 8 KiB.
- Concurrent checks of the same IP and bot share one reverse-DNS lookup.
- Module path `github.com/dkd-dobberkau/bot-verify`; GitHub Actions CI with
  vet, race tests and Trivy; actions pinned by commit SHA and base images by
  digest; Dependabot for digests, actions and Go modules.

### Security

- A transient A-record failure during forward confirmation was reported as
  "not found" by the merged A+AAAA lookup and became a cached `refuted` for a
  real crawler. The forward lookup now asks only for the queried IP's family
  (audit run 1). Tests pin how the PTR step classifies resolver failures.
- Operator lists were accepted after an `https://` source redirected to
  plain `http://`. Such redirects are now refused on every hop (audit run 1).
- The list fetcher refuses connections to non-public addresses: loopback,
  private, link-local, CGNAT, benchmarking, reserved and documentation
  ranges, local-use NAT64, and NAT64/6to4 addresses that translate to one of
  them. Skipped when an outbound proxy is configured.
- A snapshot line's ETag or Last-Modified made the origin's 304 renew the
  file's prefixes indefinitely, so anyone able to write the snapshot could
  keep chosen ranges `confirmed` past the 7-day limit (audit run 2).
- Snapshot temp-file cleanup no longer removes the temp files of a sibling
  snapshot with a longer name.
- An in-zone `-ns` name below a name the zone answers NXDOMAIN for is
  refused at start.

## 0.1.0 – 2026-11-18

- First version: single Go binary with HTTP API (`/v1/verify`, `/v1/bots`,
  `/v1/dataset`, `/healthz`).
- `bots.yaml` with 51 bots derived from goodbot-badbot's bot catalog; 27 can be
  checked by published IP list and/or forward-confirmed reverse DNS.
- Operator lists refreshed every 6 hours with conditional requests; the last
  good copy survives failed fetches.
- Dockerfile (distroless, non-root, health check via `-probe`).
