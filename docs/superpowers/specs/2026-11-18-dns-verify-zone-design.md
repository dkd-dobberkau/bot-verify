# DNS verify zone: design (2026-11-18)

Status: draft for approval (revised after builder check). Builds on `docs/idea.md` (decision 1: "A DNS zone
can be generated from the same dataset later") and the current code
(`internal/catalog`, `internal/sources`, `internal/store`, `internal/verify`).

## Intent

Webservers and WAFs should be able to check, **per incoming request**, whether
an IP really belongs to the bot its User-Agent claims, with a DNS lookup
instead of an HTTP call. DNS fits that path:
- the local resolver caches the answers;
- a lookup is fast;
- many WAFs already query DNS lists (DNSBL style), for example ModSecurity's
  `@rbl`.

Those clients need no HTTP client and no JSON.

The zone is a **verify list, not a blocklist**. A listed name means
"confirmed". The project stores no visitor data (docs/idea.md, "Why verify and
not block").

## Goals

- A DNS server that answers "is IP x bot y?" from operators' published IP
  lists, with the same verdict meaning as `/v1/verify`.
- Simple DNSBL clients must never mistake "cannot check" for "confirmed".
- It runs as its own binary on port 53, separate from the HTTP API.
- It is ready immediately after a restart, from an on-disk snapshot.

## Non-goals (for now)

- Reverse-DNS checks (bots verified only by PTR plus forward lookup). The DNS
  server never sends DNS queries of its own (see Constraints).
- TXT records explaining a verdict, DNSSEC signing, zone transfers (AXFR/IXFR).
- Sharing state between the API and the DNS binary.

## Anti-goals (a failure even if it works)

- Any path where "not checkable" (list not loaded or stale, unknown bot, or a
  bot that can still be verified another way) produces an A record, or an
  NXDOMAIN that a resolver could apply to names below it (RFC 8020). Naive clients treat
  any A record as a hit, so this would be a false `confirmed`.
- A DNS answer that triggers outbound queries. That would amplify attacks, the
  same slot-exhaustion problem the API had, made easier over UDP.
- Logging queried names. They contain visitor IPs.

## Constraints

- Same verdict principles as the API: `confirmed` only from a loaded list
  match; uncertainty never refutes (docs/verdicts.md).
- The same fetch protections apply, by reusing `sources.NewClient`: https only
  across redirects, no non-public destinations, 5 MiB body limit, per-source
  prefix cap, breadth limits.
- Go 1.27, CGO disabled, distroless nonroot image, as today.
- One new dependency, approved by the owner on 2026-11-18:
  `github.com/miekg/dns`. No other new dependencies.

## Approaches considered

1. **DNS server inside the existing bot-verify binary.** It would reuse the
   in-memory store directly. Rejected by the owner: port 53 and its
   privileges and attack surface should be separate from the HTTP API.
2. **Export rbldnsd datasets** and serve them with rbldnsd. It is a mature
   CIDR-capable DNSBL server and would need no DNS code here. Rejected for two
   reasons. It is a second daemon to run. And rbldnsd answers NXDOMAIN
   ("refuted") for a missing or still-empty dataset, which would refute real
   crawlers at startup or after fetch failures.
3. **Plain zone files for BIND, NSD or Knot.** Rejected: one record per IP, so
   millions of records for Google's ranges alone.
4. **Chosen: a separate binary `bot-verify-dns`, built on `miekg/dns`,** that
   loads `bots.yaml` and fetches the lists itself.

   How the DNS binary gets its data was a separate choice:
   - **(a) Chosen: it fetches the lists itself.** No runtime dependency on
     the API.
   - **(b) Pull `/v1/dataset` from the API.** Rejected: the DNS binary would
     depend on the API, and the link between them would need integrity
     protection.
   - **(c) A shared database.** Rejected:
     - SQLite needs a heavy pure-Go driver without cgo.
     - bbolt allows only one process to open the file at a time.
     - Postgres or Redis means another service to run.

   A **JSONL snapshot file per binary** keeps the benefit a database would
   have given, a warm start, without coupling the two binaries.

## Decided

### Query form and answers

Query name: `<reversed address>.<bot-id>.<zone>`.

| Address | Query name |
|---|---|
| IPv4 | Reversed octets: `1.66.249.66.gptbot.verify.example` for 66.249.66.1 |
| IPv6 | 32 reversed nibbles, as in `ip6.arpa`, followed by `.<bot-id>.<zone>` |
| IPv4-mapped IPv6 | Treated as IPv4, as in the API |

The zone is set by a flag (`-zone`). The bot id is the `bots.yaml` id.

| Case | Answer |
|---|---|
| Address is in a loaded, current IP list of the bot | **NOERROR, A `127.0.0.2`** (only for QTYPE A; other QTYPEs on that name give NOERROR without answer) |
| Bot has only IP lists, all of them are loaded and current, and none contains the address | **NXDOMAIN** (refuted) |
| Any list of the bot is not loaded or older than 7 days | **NOERROR without answer (NODATA)** (not checkable) |
| Bot is `not_checkable`, has only reverse-DNS rules, or is unknown | **NODATA** |
| Bot has IP lists **and** reverse-DNS suffixes, and the address is in no loaded list | **NODATA**, because reverse DNS might still confirm it, so a list miss is not a refutation. This affects 13 bots today, including googlebot, bingbot, applebot and ahrefsbot (owner decision, 2026-11-18) |
| A name above a complete address: `<bot-id>.<zone>`, a partial octet path such as `66.gptbot.<zone>`, or a partial nibble path | **NODATA**, never NXDOMAIN. RFC 8020 resolvers would otherwise treat everything below the name as non-existent and refute real addresses |
| Names inside the zone that cannot become an address (a non-numeric label, an octet over 255, too many labels) | **NXDOMAIN**. Nothing valid exists below them |
| Server failure (should not happen) | SERVFAIL |

Only 8 bots can be refuted by NXDOMAIN today (lists only): gptbot,
chatgpt-user, oai-searchbot, claudebot, claude-user, shapbot, perplexitybot,
duckduckbot.

Why NODATA for "not checkable" (owner decision, 2026-11-18): naive clients see
no A record, so it never reads as confirmed. It is not NXDOMAIN, so it never
reads as refuted. Resolvers cache it through the SOA minimum and do not treat
it as a server fault. SERVFAIL would make resolvers retry all name servers and
can get the server marked as broken.

### What WAFs can do with it

Both uses are supported, and the README shows one example of each:
- **Allow confirmed bots** (any DNSBL client, e.g. ModSecurity `@rbl`, which
  only sees "resolves" or "does not resolve"): skip the challenge when the
  name resolves.
- **Block spoofers** (a client that sees the RCODE, e.g. OpenResty or nginx
  with Lua, or HAProxy with Lua): block on NXDOMAIN only, pass or challenge
  on NODATA and on lookup failure.

### Maximum list age (both binaries)

A list whose last successful fetch (or 304) is older than **7 days** counts as
not loaded:
- in the DNS answers (NODATA);
- in `/v1/verify` (`not_checkable`, reason `source data stale`);
- in `/readyz`;
- when the snapshot is loaded.

This replaces the "lists are kept for good" limitation in SECURITY.md.

### Snapshot (both binaries)

- **Flag.** `-snapshot <path>` on `bot-verify` and `bot-verify-dns`; the
  feature is off when the flag is unset.
- **Format.** JSONL, one line per source: `url`, `fetched_at` (RFC 3339 UTC),
  `etag`, `last_modified`, `prefixes` (array of CIDR strings).
- **Writing.** After every refresh cycle that changed the store, write a temp
  file in the same directory, then `rename` it over the old one. File mode
  0600.
- **Loading at start**, before the first fetch. Each line goes through the
  same acceptance as a fresh fetch: parse, IPv4-mapped normalisation,
  breadth limit, prefix cap. A line is dropped, with a warning naming the URL
  and not the prefixes, if it:
  - is malformed;
  - fails validation;
  - names a URL that is not in the current catalog;
  - has a `fetched_at` older than **7 days**.
- **After loading.** The first refresh cycle runs immediately as today.
  Stored ETag and Last-Modified make it mostly 304s.
- **Readiness.** A source loaded from the snapshot counts as loaded, so
  `/readyz` and the DNS answers are ready without waiting for the first
  fetch.

### DNS server behaviour

- **Transport.** UDP and TCP on the same address (`-listen`), EDNS0
  supported, truncation to TCP for large answers. Real answers are tiny.
- **Apex.** SOA and NS records for the zone, from flags: `-zone`, `-ns` (one
  or more server names), `-hostmaster`.
- **Reachability** (builder's call, confirmed in review). The zone works both
  ways:
  - publicly delegated from a parent zone;
  - as a stub or forward zone in an operator's own resolver.

  NS names inside the zone get glue A/AAAA records from an optional flag
  (e.g. `-ns ns1.verify.example=192.0.2.53`). Their labels are reserved and
  must not clash with bot ids; the catalog check fails at start if one does.
- **TTLs.** Positive answers 300 s. The SOA minimum (the negative-cache TTL,
  used for NXDOMAIN and NODATA) is 300 s, matching the API's `Cache-Control`.
- **Rate limiting** per source address against spoofed-source reflection:
  per IPv4 address and per IPv6 /56, with a bounded table.
- **Out-of-zone queries.** Names outside the zone get REFUSED. The server is
  never a recursive resolver.
- **Logging.** Aggregate counters only: queries and answers per RCODE. Never
  query names or client addresses.
- **Container health check.** `-probe` asks the server for its own SOA over
  UDP.

### Packaging

- New binary `cmd/bot-verify-dns`, built from the same module. It reuses
  catalog, sources, store, refresh and the new snapshot package.
- Docker: a second image target from the same Dockerfile, distroless nonroot.
- README: a DNS section with two examples, a ModSecurity `@rbl` rule that
  skips the challenge for confirmed bots, and an OpenResty/Lua snippet that
  blocks only on NXDOMAIN.
- SECURITY.md: what the DNS answers mean, the NODATA and NXDOMAIN semantics,
  that resolvers cache answers for up to 300 s, and that the maximum list age
  is now 7 days.

## Left to the builder

- Package layout. A suggestion: `internal/snapshot` (read/write JSONL),
  `internal/dnszone` (name parsing and answer decision, pure functions,
  heavily table-tested), `cmd/bot-verify-dns`.
- How the snapshot validation reuses the parser acceptance. Exporting a
  validation function from `internal/sources` is fine.
- The exact rate-limit numbers and table size, and the default listen port.
  Distroless nonroot cannot bind 53 without a capability, so a default of
  `:5353` with port mapping in the docs is acceptable.
- Whether the verdict decision is shared with `internal/verify` or kept
  separate, as long as the table above holds and tests pin it.
- For a bot with several lists where one matches and another is not loaded:
  answer A, the same as `/v1/verify`.

## Decisions from review (2026-11-18)

- "Not checkable" is NODATA, not SERVFAIL (owner).
- The 7-day maximum list age applies at runtime in both binaries (owner).
- Bots with list and reverse DNS: a list miss gives NODATA (owner).
- WAF use: the zone supports both "allow confirmed" and "block refuted", and
  the README shows both (builder's call; the RCODEs already carry the
  distinction).
- Names above a complete address give NODATA, because of RFC 8020 (builder's
  call from review).
- Public delegation and stub zones with optional in-zone glue (builder's
  call from review).

## Changes after security audit run 2 (2026-11-19)

- Rate limiting is keyed per IPv4 /24 instead of per IPv4 address, as in
  authoritative RRL, so a spoofer cannot reflect one burst per address at a
  whole /24 (owner). IPv6 stays per /56. A full table evicts idle entries
  instead of being wiped.
- TCP, the fallback for rate-limited resolvers, has a connection cap in
  total and per source, set by flags (`-tcp-max-conns` 512,
  `-tcp-max-per-source` 16), plus a 2 s idle timeout and 32 queries per
  connection (owner).
