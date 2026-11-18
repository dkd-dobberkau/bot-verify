# Changelog

## Unreleased

- Fix: a transient A-record failure during forward confirmation was reported
  as "not found" by the merged A+AAAA lookup and became a cached `refuted` for
  a real crawler. The forward lookup now asks only for the queried IP's family.
- Fix: operator lists were accepted after an `https://` source redirected to
  plain `http://`, so plaintext content could confirm spoofed IPs. Such
  redirects are now refused.
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
