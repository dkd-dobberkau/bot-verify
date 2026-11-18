# Security

## Reporting

Please do not open a public issue for a security problem. Report it privately,
through a GitHub security advisory on this repository or directly to the
maintainer, with steps to reproduce.

**The most serious class of bug is a false `confirmed`**: any input or setup in
which a client that is not the claimed bot gets confirmed as it. Next comes
anything that makes a real crawler `refuted`, or lets one client degrade the
service for others.

## What bot-verify does and does not promise

- An answer is only as good as the IP it is asked about. Consumers must take
  the client IP from the TCP peer or from a proxy they control, never from a
  client-supplied `X-Forwarded-For` (see the README, "Taking the client IP").
- `confirmed` means the operator's published list or reverse-DNS rule matches.
  It is no stronger than what the operator publishes.
- `not_checkable` is not a negative answer. Do not block on it.
- No visitor data is stored, and queried IPs are not logged.

## Known limitations

- **Lists expire after 7 days.** A list whose last successful fetch (or 304)
  is older than 7 days counts as not loaded: it neither confirms nor refutes,
  `/v1/verify` gives `not_checkable` with reason `source data stale`, and it
  does not count towards `/readyz`. Within those 7 days a cloud address the
  operator has since handed to another customer can still be `confirmed`.
- **Broad reverse-DNS suffixes:** `yandex.*`, `baidu.*`, `google.com` and
  `seznam.cz` are only safe while their operators' name servers return no
  customer IPs for names under them. A sample on 2026-11-18 found none (see
  [docs/bots.md](docs/bots.md)), but nothing checks this automatically yet.
- **Cacheable transient answers:** `not_checkable` answers (DNS failure, list not
  loaded) are sent with `Cache-Control: public, max-age=300`, like definite
  ones, so a shared cache holds them for up to 5 minutes.
- **The reverse-DNS cache can be flushed:** it is cleared when it reaches
  100,000 entries, so a client sending many distinct IPs empties it. That costs
  extra lookups, not wrong answers.
- **Public instances** run DNS lookups for addresses that callers choose. Run
  one behind a reverse proxy with per-client rate limiting. Each verify request
  is capped at 3 s and at most 64 reverse-DNS checks run at once.
- **Outbound proxy:** when `HTTPS_PROXY` is set, the fetcher's refusal of
  non-public destinations is off, because it connects to the proxy. The proxy
  must then block internal destinations itself.
- **Not covered:** Web Bot Auth signatures, and bots whose operators publish
  nothing.
