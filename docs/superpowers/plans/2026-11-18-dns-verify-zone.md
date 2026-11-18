# DNS Verify Zone Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A separate `bot-verify-dns` binary answers "is IP x bot y?" over DNS from operators' IP lists. Both binaries gain JSONL snapshots for a warm start and a 7-day maximum list age.

**Architecture:**
- **Store:** reports per-list freshness (`Loaded`, `Stale`, `NotLoaded`) against a 7-day maximum age. `verify`, the API and the new DNS code all decide on that.
- **`internal/snapshot`:** reads and writes the JSONL warm-start file, revalidating every line with the parser's acceptance rules.
- **`internal/dnszone`:** a pure name parser and answer decision, plus a `miekg/dns` handler with SOA/NS/glue, REFUSED outside the zone, and response rate limiting.
- **`cmd/bot-verify-dns`:** wires catalog, fetch client, store, refresh, snapshot and the DNS server.

**Tech Stack:** Go 1.27, standard library, `go.yaml.in/yaml/v3`, and new `github.com/miekg/dns v1.1.73` (approved by the owner on 2026-11-18).

**Spec:** `docs/superpowers/specs/2026-11-18-dns-verify-zone-design.md`

## Global Constraints

**Answers**
- Answers exactly as in the spec table:
  - confirmed → NOERROR with A `127.0.0.2`, TTL 300;
  - refuted → NXDOMAIN;
  - not checkable → NOERROR with no answer (NODATA);
  - SERVFAIL only for internal failures.
- NXDOMAIN and NODATA carry the zone SOA in the authority section. SOA minimum is 300.
- An A record is never answered unless a loaded, fresh list of the bot contains the address.
- No NXDOMAIN for a name that is a prefix of any valid address name. This covers:
  - partial paths;
  - `<bot-id>.<zone>`;
  - IPv4 names whose four labels are all single hex digits, because they are also IPv6 nibble prefixes.

**Data**
- Maximum list age: `store.MaxAge = 7 * 24 * time.Hour`, measured from the last successful fetch or 304. It applies at runtime in both binaries and when loading a snapshot.
- Snapshot: JSONL with fields `url`, `fetched_at` (RFC 3339 UTC), `etag`, `last_modified`, `prefixes`. Written to a temp file in the same directory, then renamed, with file mode 0600. The feature is off unless `-snapshot` is set.

**Privacy**
- Never log queried names, client addresses or prefixes. The DNS binary logs only aggregate counters.

**Fetching**
- Reuse `sources.NewClient` for fetches. No other new dependencies.

**Build**
- `go.mod` stays at `go 1.27`. The image stays distroless nonroot. The DNS image defaults to `-listen :5353`.

## Review Focus

1. **Collisions between IPv4 names and IPv6 prefixes.** Example: `1.0.0.2.gptbot.<zone>`, refuted for IPv4 2.0.0.1, is also a prefix of 2001::/16 names. It must give NODATA, not NXDOMAIN. Test in Task 4.
2. **Case and trailing dots.** Mixed-case query names (`1.66.249.66.GPTBot.Verify.Example.`) and the zone given with or without a trailing dot must match. Test in Task 4.
3. **Snapshot written at the moment the source is updated.** A crash between writing the temp file and renaming it must leave the old snapshot intact, and a leftover temp file must not be read. Test in Task 3.
4. **List age right at the 7-day limit.** A list exactly 7 days old counts as fresh. One second more counts as stale, and for Verify that is not_checkable with the reason `source data stale`, never refuted. Test in Task 1.
5. **TCP and truncation.** A query over TCP gets the same answer. A UDP response over the rate limit is answered with the TC bit and no answer, never dropped silently, so honest resolvers retry over TCP. Test in Task 5.

---

### Task 1: List freshness and 7-day maximum age

**Files:**
- Modify: `internal/store/store.go`, `internal/verify/verify.go`, `internal/api/api.go`
- Test: `internal/store/store_test.go`, `internal/verify/verify_test.go`, `internal/api/api_test.go`

**Interfaces:**
- Produces:
  - `const MaxAge = 7 * 24 * time.Hour`
  - `type ListState int` with constants `NotLoaded`, `Stale`, `Loaded`
  - `func (s *Store) Lookup(url string, ip netip.Addr, now time.Time) (state ListState, matched bool, fetchedAt time.Time)`. `matched` is true only when the state is `Loaded`.
  - `func (s *Store) State(url string, now time.Time) ListState`
- `Store.Contains` is removed. Update its callers.
- `verify.ReasonStale = "source data stale"`.

- [ ] **Step 1: Write the failing tests**
  - `TestLookupStates` (store):
    - an unset URL gives `NotLoaded`;
    - a snapshot with `FetchedAt = now - MaxAge` gives `Loaded` and matches;
    - `now - MaxAge - time.Second` gives `Stale` with `matched == false`, even for an address inside the prefix.
  - `TestVerify_StaleListNotCheckable` (verify): with a stale list holding the IP, `listbot` gives `not_checkable`, method `ip_list`, reason `source data stale`.
  - `TestVerify_StaleListNeverRefutes` (verify): with a stale list not holding the IP, the result is `not_checkable`, not `refuted`.
  - `TestReadyzCountsOnlyFreshLists` (api): with only a stale list, `/readyz` gives 503 `no_sources_loaded` after a refresh cycle. `/healthz` `sources_loaded` counts fresh lists only.
- [ ] **Step 2: Run `go test ./internal/...`. Expected: FAIL (undefined `Lookup`, `ReasonStale`).**
- [ ] **Step 3: Implement.**
  - **Store.** `Lookup` and `State` compare `now.Sub(FetchedAt) > MaxAge`.
  - **Verify.** Use `Lookup` with `v.now()`. A bot with any `NotLoaded` list gets `ReasonNotLoaded`. Otherwise, a bot with any `Stale` list gets `ReasonStale`, using the same not_checkable branch as today.
  - **API.** `sourceCounts` counts `State(...) == Loaded`, with `time.Now`.
- [ ] **Step 4: Run `go test -race ./...`. Expected: PASS.**
- [ ] **Step 5: Commit** `feat: lists older than 7 days count as not loaded`, including the SECURITY.md line that replaces "Old lists are kept for good" and a docs/verdicts.md note.

---

### Task 2: Exported prefix validation for reuse

**Files:**
- Modify: `internal/sources/parse.go`
- Test: `internal/sources/parse_test.go`

**Interfaces:**
- Produces: `func ValidatePrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error)`. It applies `acceptPrefix` to each prefix (IPv4-mapped normalisation, breadth check, masking) and then `nonEmpty` (empty list and `MaxPrefixes`).

- [ ] **Step 1: Write the failing test** `TestValidatePrefixes`:
  - `[::ffff:198.51.100.0/120]` becomes `[198.51.100.0/24]`;
  - `[0.0.0.0/0]` gives an error;
  - an empty slice gives `errors.Is(err, ErrNoPrefixes)`;
  - `MaxPrefixes+1` entries give an error.
- [ ] **Step 2: Run `go test ./internal/sources/`. Expected: FAIL.**
- [ ] **Step 3: Implement.** Make both parsers call `ValidatePrefixes` on their collected slice instead of calling `acceptPrefix` and `nonEmpty` inline.
- [ ] **Step 4: Run `go test ./internal/sources/`. Expected: PASS.**
- [ ] **Step 5: Commit** `refactor: expose prefix validation for snapshot loading`.

---

### Task 3: JSONL snapshot

**Files:**
- Create: `internal/snapshot/snapshot.go`, `internal/snapshot/snapshot_test.go`

**Interfaces:**
- Consumes: `store.Store` (`Get`, `Set`, `Version`), `store.MaxAge`, `sources.ValidatePrefixes`, `sources.FetchState`, `catalog.Catalog`
- Produces:
  - `func Write(path string, cat *catalog.Catalog, st *store.Store) error` writes one line per catalog URL that has a stored snapshot.
  - `func Load(path string, cat *catalog.Catalog, st *store.Store, now time.Time) (loaded int, warnings []string, err error)` stores valid lines with `st.Set`. A missing file is not an error: it returns `0, nil, nil`. Warnings name the URL and the reason, never prefixes.

- [ ] **Step 1: Write the failing tests**
  - `TestRoundTrip`: two sources set, `Write`, then `Load` into a new store. Prefixes, `FetchedAt` (to the second), ETag and Last-Modified are equal.
  - `TestLoadDropsBadLines`: a file with one valid line plus:
    - a malformed JSON line;
    - a line for a URL not in the catalog;
    - a line with `fetched_at` older than `MaxAge`;
    - a line with prefix `0.0.0.0/0`.

    Expect `loaded == 1` and four warnings, none containing a prefix string.
  - `TestWriteIsAtomic` (Review Focus 3):
    - after `Write`, the directory holds only the snapshot file, with mode 0600;
    - when the destination directory becomes read-only between writes, `Write` returns an error and the previous file content is unchanged;
    - a stray `*.tmp` file in the directory is ignored by `Load`.
  - `TestLoadMissingFile`: gives `0, nil, nil`.
- [ ] **Step 2: Run `go test ./internal/snapshot/`. Expected: FAIL.**
- [ ] **Step 3: Implement.**
  - `Write` uses `os.CreateTemp(dir, ".snapshot-*.tmp")`, `Chmod 0600`, one `json.Encoder` line per source, `Sync`, `Close`, then `os.Rename`.
  - `Load` reads lines with `bufio.Scanner`, with a 6 MiB max token so a full 5 MiB list fits.
- [ ] **Step 4: Run `go test -race ./internal/snapshot/`. Expected: PASS.**
- [ ] **Step 5: Commit** `feat: JSONL snapshot of operator lists for warm start`.

---

### Task 4: Name parsing and answer decision

**Files:**
- Create: `internal/dnszone/answer.go`, `internal/dnszone/answer_test.go`

**Interfaces:**
- Consumes: `catalog.Catalog`, `store.Store.Lookup`
- Produces:
  - `type Kind int` with constants `Apex`, `BotOnly`, `Partial`, `Address`, `Invalid`, `Outside`
  - `type Name struct { Kind Kind; Bot string; Addr netip.Addr; AmbiguousIPv4 bool }`
  - `func ParseName(qname, zone string) Name`. Lowercases and trims the trailing dot of both arguments.
  - `type Answer int` with constants `AnswerA`, `AnswerNXDomain`, `AnswerNoData`, `AnswerRefused`
  - `func Decide(cat *catalog.Catalog, st *store.Store, now time.Time, n Name) Answer`

Parsing rules, as labels left of the zone:
- **No labels:** `Apex`.
- **The label next to the zone** is the bot id. With no further labels: `BotOnly`.
- **Remaining labels** are read as the reversed address:
  - four labels that are decimal octets 0-255 without leading zeros: an IPv4 `Address`. `AmbiguousIPv4` is set when every label is a single character in `0-9`.
  - 32 labels that are single hex nibbles: an IPv6 `Address`.
  - one to three octet labels, or 1–31 nibble labels: `Partial`.
  - anything else: `Invalid`.
- **IPv4-mapped IPv6** is unmapped to IPv4.
- **A name not under the zone:** `Outside`.

Decision rules:
- `Outside` gives `AnswerRefused`.
- `Apex`, `BotOnly` and `Partial` give `AnswerNoData`.
- `Invalid` gives `AnswerNXDomain`.
- For an `Address`:
  - an unknown bot, a bot with no IP sources, or a `not_checkable` bot gives NoData;
  - a match in any `Loaded` list gives A;
  - any list `NotLoaded` or `Stale` gives NoData;
  - a bot with `RDNSSuffixes` gives NoData;
  - an `AmbiguousIPv4` name gives NoData;
  - otherwise NXDomain.

- [ ] **Step 1: Write the failing tests**
  - `TestParseName`: a table covering every rule above, including:
    - Review Focus 2: `1.66.249.66.GPTBot.Verify.Example.` with zone `verify.example` gives `Address` 66.249.66.1, bot `gptbot`;
    - a full IPv6 name for `2001:4860:4801:10::1`;
    - `256.1.1.1` gives `Invalid`;
    - `01.1.1.1` gives `Invalid`;
    - `66.gptbot` gives `Partial`;
    - `example.com.` gives `Outside`.
  - `TestDecide`: one case per row of the spec answer table, using a catalog with `listbot` (lists only), `bothbot` (list plus rDNS), `dnsbot` (rDNS only) and `nobot` (not_checkable), plus:
    - a stale list;
    - one matching list beside one not-loaded list, which gives A;
    - Review Focus 1: `1.0.0.2.listbot` with every list loaded and no match gives `AnswerNoData`, while `1.0.0.20.listbot` gives `AnswerNXDomain`.
  - `TestDecideNeverAOnStaleOrMissing`: for every catalog bot and every list state other than `Loaded`, `Decide` never returns `AnswerA`.
- [ ] **Step 2: Run `go test ./internal/dnszone/`. Expected: FAIL.**
- [ ] **Step 3: Implement** `ParseName` and `Decide` as pure functions.
- [ ] **Step 4: Run `go test ./internal/dnszone/`. Expected: PASS.**
- [ ] **Step 5: Commit** `feat: DNS name parsing and answer decision for the verify zone`.

---

### Task 5: DNS handler, apex records, rate limiting

**Files:**
- Create: `internal/dnszone/server.go`, `internal/dnszone/ratelimit.go`, `internal/dnszone/server_test.go`
- Modify: `go.mod`, `go.sum` (`go get github.com/miekg/dns@v1.1.73`)

**Interfaces:**
- Consumes: `ParseName`, `Decide`
- Produces:
  - `type Config struct { Zone string; NS []NameServer; Hostmaster string; Catalog *catalog.Catalog; Store *store.Store; Now func() time.Time; Limiter *Limiter }`
  - `type NameServer struct { Name string; Addrs []netip.Addr }`
  - `func NewHandler(cfg Config) dns.Handler`
  - `func NewLimiter(ratePerSecond, burst int) *Limiter` with `func (l *Limiter) Allow(src netip.Addr, now time.Time) bool`. The key is the IPv4 address or the IPv6 /56. The table is capped at 100,000 entries and cleared when full, as in `rdns`.
  - `type Counters struct` with atomic fields per answer kind, and `func (h) Counters() *Counters`. The counters are exposed through a type assertion on the returned handler, or `NewHandler` returns `*Handler`.

Behaviour:
- **Apex.** SOA: serial `uint32(store.Version())` when nonzero, otherwise 1. Refresh 3600, retry 600, expire 86400, minimum 300. NS records as configured.
- **Glue.** A/AAAA for in-zone NS names. NS names are matched exactly, before `ParseName` runs, so they never reach the address rules.
- **Answer A.** `127.0.0.2`, TTL 300, authoritative bit set.
- **NXDOMAIN and NODATA.** SOA in the authority section.
- **REFUSED** for `Outside` names. Only QCLASS IN is answered; other classes get REFUSED.
- **Rate limit.** Over the limit on UDP: a reply with TC set and empty sections. Over TCP: never limited.
- **Error handling.** A panic or internal error gives SERVFAIL.
- **Limits.** The production `cmd` uses 200 qps with a burst of 400 per key.

- [ ] **Step 1: Write the failing tests.** Start the handler on `127.0.0.1:0` with UDP and TCP `dns.Server`s and query with `dns.Client`. Name the tests `TestServe_<case>`:
  - A confirmed, with TTL 300 and the AA bit;
  - NXDOMAIN with SOA minimum 300;
  - NODATA for a not-loaded list;
  - SOA and NS at the apex;
  - glue A for `ns1.<zone>` configured with an address;
  - REFUSED for `example.com.`;
  - the same answer over TCP (Review Focus 5);
  - `TestLimiterTruncates`: with a limiter of rate 1 and burst 1, the second UDP query from the same address within one second gets `Truncated == true` and no answer, and the same query over TCP still gets the A answer (Review Focus 5).
- [ ] **Step 2: Run `go test ./internal/dnszone/`. Expected: FAIL.**
- [ ] **Step 3: Implement** with `dns.HandlerFunc`, `dns.Msg.SetReply`, `SetRcode` and an `Authoritative` reply.
- [ ] **Step 4: Run `go test -race ./internal/dnszone/`. Expected: PASS.**
- [ ] **Step 5: Commit** `feat: authoritative DNS handler for the verify zone`.

---

### Task 6: Snapshot wiring in bot-verify

**Files:**
- Modify: `cmd/bot-verify/main.go`, `cmd/bot-verify/main_test.go`, `internal/api/api.go`, `internal/api/api_test.go`

**Interfaces:**
- Consumes: `snapshot.Load`, `snapshot.Write`, `store.Version`
- Produces:
  - flag `-snapshot <path>` (default `""`, which means off);
  - a readiness rule in `/readyz`:
    - `ready` when at least one list is `Loaded`, or when the catalog has no sources and a refresh has run;
    - otherwise `starting` before the first refresh cycle;
    - otherwise `no_sources_loaded`.

- [ ] **Step 1: Write the failing tests**
  - `TestRunWritesAndLoadsSnapshot`:
    - first `run()` against an httptest TLS source with `-snapshot <tmp>/s.jsonl`: wait until `sources_loaded == 1`, then cancel;
    - second `run()` with the source now answering 500: `/healthz` reports `sources_loaded == 1` on its first successful response, and `/readyz` gives 200.
  - Update `TestReadyz` for the new rule: a store holding a loaded list but not yet refreshed gives 200 `ready`.
- [ ] **Step 2: Run `go test ./cmd/... ./internal/api/`. Expected: FAIL.**
- [ ] **Step 3: Implement.**
  - Call `snapshot.Load` before starting the scheduler and log its warnings.
  - In the scheduler callback, after `Refresh`, call `snapshot.Write` when `st.Version()` changed since the last write. Log write errors; they are not fatal.
- [ ] **Step 4: Run `go test -race ./...`. Expected: PASS.**
- [ ] **Step 5: Commit** `feat: bot-verify keeps a JSONL snapshot for warm starts`.

---

### Task 7: bot-verify-dns binary

**Files:**
- Create: `cmd/bot-verify-dns/main.go`, `cmd/bot-verify-dns/main_test.go`

**Interfaces:**
- Consumes: `catalog.Load`, `sources.NewClient`, `store`, `snapshot`, `dnszone.NewHandler`, `dnszone.NewLimiter`
- Produces: `func run(ctx context.Context, args []string, stdout io.Writer) error` with these flags:

  | Flag | Default | Meaning |
  |---|---|---|
  | `-listen` | `:5353` | UDP and TCP address |
  | `-bots` | `bots.yaml` | catalog file |
  | `-zone` | required | zone name |
  | `-ns` | required, at least one | repeatable, `name` or `name=ip[,ip]` |
  | `-hostmaster` | required | SOA mailbox |
  | `-refresh` | `6h` | refresh interval |
  | `-snapshot` | | snapshot path |
  | `-probe` | | health check |
  | `-version` | | print version |

  - **Startup checks.** Fail when, for an in-zone NS name, the label directly left of the zone (the position `ParseName` reads as the bot id) equals a catalog bot id, or when `-zone` is empty or not a valid domain.
  - **Readiness line.** Print `listening on <udp addr>` to stdout once both UDP and TCP servers are up.
  - **`-probe`.** Queries the zone SOA over UDP at the `-listen` address, with an empty host meaning 127.0.0.1, and a 3 s timeout.
  - **Counters.** Logged every 10 minutes and at shutdown, as one slog line of aggregate counters.

- [ ] **Step 1: Write the failing tests**
  - `TestRunAnswersFromFetchedList`:
    - an httptest TLS source with `{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}` and a catalog with bot `listbot`;
    - `run()` on `127.0.0.1:0`, with the test overriding the fetch client as in the API test;
    - poll a `dns.Client` query for `7.2.0.192.listbot.<zone>` until it gives an A answer;
    - then `8.51.100.198.listbot.<zone>` gives NXDOMAIN;
    - cancel `ctx`; `run` returns nil within 5 s.
  - `TestRunRejectsNSLabelClash`: `-ns listbot.<zone>=192.0.2.53` gives an error naming the clash.
  - `TestProbe`: healthy against a running server, and an error against a closed port.
- [ ] **Step 2: Run `go test ./cmd/bot-verify-dns/`. Expected: FAIL.**
- [ ] **Step 3: Implement.** Mirror `cmd/bot-verify/main.go`: `signal.NotifyContext` and graceful `Shutdown` of both DNS servers.
- [ ] **Step 4: Run `go test -race ./...`. Expected: PASS.**
- [ ] **Step 5: Commit** `feat: bot-verify-dns binary serving the verify zone`.

---

### Task 8: Image, docs, changelog

**Files:**
- Modify: `Dockerfile`, `README.md`, `SECURITY.md`, `docs/verdicts.md`, `CHANGELOG.md`, `.github/workflows/ci.yml` (only if the build needs it)

- [ ] **Step 1: Dockerfile.**
  - The builder stage builds both binaries.
  - Add a final stage `dns` (`FROM … AS dns`) with `ENTRYPOINT ["/app/bot-verify-dns"]`, `EXPOSE 5353/udp 5353/tcp` and `HEALTHCHECK … ["/app/bot-verify-dns","-probe"]`.
  - Keep the API stage as the default last stage, so plain `docker build` still produces the API image.
  - Verify with:
    - `docker build --target dns -t bot-verify-dns .`
    - `docker run --rm -p 5353:5353/udp bot-verify-dns -zone verify.example -ns ns1.verify.example=127.0.0.1 -hostmaster hostmaster.verify.example`
    - `dig @127.0.0.1 -p 5353 1.216.73.216.claudebot.verify.example A`

    Expected: `127.0.0.2` once the lists are loaded.
- [ ] **Step 2: README.** Add a DNS section covering:
  - the query form;
  - the answer table;
  - a stub-zone example for Unbound;
  - a ModSecurity `@rbl` rule that skips the challenge for confirmed bots;
  - an OpenResty `resty.dns.resolver` snippet that blocks only on NXDOMAIN;
  - the `-snapshot` flag for both binaries.
- [ ] **Step 3: SECURITY.md.** Cover:
  - the DNS answer semantics;
  - resolver caching of up to 300 s;
  - truncation-based rate limiting;
  - that a NODATA must never be treated as refuted.
- [ ] **Step 4: docs/verdicts.md and CHANGELOG.** Add a DNS section with the answer rules, the maximum list age and the snapshot.
- [ ] **Step 5: Run `go test -race ./...` and `go vet ./...`. Expected: PASS. Commit** `docs: DNS verify zone, snapshots and maximum list age`.
