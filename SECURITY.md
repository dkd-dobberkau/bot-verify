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

- **Old lists are kept for good.** If refreshes keep failing, a list stays in use
  however old it is (`data_age_seconds` shows the age). Several lists are cloud
  ranges, so an address the cloud has since handed to another customer could stay
  `confirmed`. A maximum age is planned.
- **Broad reverse-DNS suffixes:** `yandex.*` and `baidu.*` are taken from the
  operators' docs. It is not yet verified that their cloud offerings cannot hand
  out forward-confirmable names under those zones. See [docs/bots.md](docs/bots.md).
- **Cacheable transient answers:** `not_checkable` answers (DNS failure, list not
  loaded) are sent with `Cache-Control: public, max-age=300`, like definite
  ones, so a shared cache holds them for up to 5 minutes.
- **The reverse-DNS cache can be flushed:** it is cleared when it reaches
  100,000 entries, so a client sending many distinct IPs empties it. That costs
  extra lookups, not wrong answers.
- **Public instances** run DNS lookups for addresses that callers choose. Run
  one behind a reverse proxy with per-client rate limiting. Each verify request
  is capped at 3 s and at most 64 reverse-DNS checks run at once.
- **Not covered:** Web Bot Auth signatures, and bots whose operators publish
  nothing.
