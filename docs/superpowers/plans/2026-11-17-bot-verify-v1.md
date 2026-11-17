# bot-verify v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single Go binary that collects bot operators' published IP lists, checks reverse DNS live, and answers "is IP x really bot y?" over HTTP with `confirmed`, `refuted` or `not_checkable`.

**Architecture:** `bots.yaml` lists every bot and how its operator says to verify it. A built-in scheduler fetches the IP-list sources every 6 hours into an in-memory store and keeps the last good copy when a fetch fails. A verifier checks the IP lists first, then forward-confirmed reverse DNS, and the HTTP API exposes the verdict, the bot list and the normalised dataset.

**Tech Stack:** Go 1.27 (local `go1.27.4`), standard library (`net/netip`, `net/http`, `net`), `go.yaml.in/yaml/v3` as the only dependency.

**Spec:** `docs/idea.md` (sections "The idea", "What we already know", "Decisions")

## Global Constraints

- Module path: `bot-verify`. Rename it once a remote exists.
- `go.mod` has `go 1.27`. CI and the Docker image use the same Go version.
- No visitor data is stored or logged. The API logs only method, path, status and duration, never the `ip` query parameter.
- Verdict strings are exactly `confirmed`, `refuted`, `not_checkable`. Method strings are exactly `ip_list`, `rdns`, `none`.
- The refresh interval defaults to 6 hours and is sent with `If-None-Match`/`If-Modified-Since`. A failed fetch keeps the last good snapshot.
- Reverse DNS is forward-confirmed: PTR, then suffix match, then the forward lookup must contain the same IP.
- Every source URL in `bots.yaml` uses `https://`.
- The docs must state that consumers take the client IP from a trusted proxy hop only, never from a client-supplied `X-Forwarded-For`.
- All text is UTF-8.

## Review Focus

1. IPv4-mapped IPv6 input (`::ffff:66.249.66.1`) is treated as the IPv4 address. Test in Task 6.
2. A source that returns 200 with empty or garbled content leaves the last good snapshot untouched and is never stored as zero prefixes. Test in Tasks 3 and 4.
3. Suffix boundaries: a PTR of `evilgooglebot.com.` must not match the suffix `googlebot.com`, and trailing dots are handled. Test in Task 5.
4. A DNS timeout or SERVFAIL gives `not_checkable` (reason `dns lookup failed`), not `refuted`, and is not cached. Tests in Tasks 5 and 6.
5. Before the first fetch finishes, a bot that has only IP-list sources gives `not_checkable` (reason `source data not loaded`), not `refuted`. Test in Task 6.

---

### Task 1: Scaffold and catalog loader

**Files:**
- Create: `go.mod`, `internal/catalog/catalog.go`, `internal/catalog/catalog_test.go`, `internal/catalog/testdata/valid.yaml`, `internal/catalog/testdata/invalid_*.yaml`
- Modify: `.gitignore` (create; entries `/bot-verify`, `.playwright-mcp/`)

**Interfaces:**
- Produces:
  - `type IPSource struct { URL string \`yaml:"url"\`; Format string \`yaml:"format"\` }`
  - `type Bot struct { ID, Name string; UATokens []string \`yaml:"ua_tokens"\`; IPSources []IPSource \`yaml:"ip_sources"\`; RDNSSuffixes []string \`yaml:"rdns_suffixes"\`; NotCheckable string \`yaml:"not_checkable"\`; Docs string }`
  - `type Catalog struct { Bots []Bot }` with `func (c *Catalog) Get(id string) (Bot, bool)`
  - `func Load(path string, knownFormats func(string) bool) (*Catalog, error)`
  - `func (b Bot) Checkable() bool` is true when `IPSources` or `RDNSSuffixes` is non-empty.

- [ ] **Step 1: `go mod init bot-verify`, `go get go.yaml.in/yaml/v3`**

- [ ] **Step 2: Write the failing tests**

`valid.yaml` holds three bots: `googlebot` (one `google-prefixes` source plus suffixes `googlebot.com`, `google.com`), `petalbot` (suffix only), `awario` (`not_checkable: "Operator says: do not try to identify the bots via IP"`).

- `TestLoadValid`: no error, `len(Bots)==3`, `Get("petalbot")` found with `RDNSSuffixes == ["petalsearch.com"]`, `Get("awario").Checkable()==false`, `Get("nope")` not found.
- `TestLoadRejects`: a table test, one fixture per case, each returning a non-nil error whose message names the bot id. The cases are a duplicate id; an id not matching `^[a-z0-9-]{1,64}$`; a bot with both sources and `not_checkable`; a bot with neither; an unknown `format`; an `http://` URL; a suffix with a leading dot or uppercase letters.

The tests pass `knownFormats = func(f string) bool { return f == "google-prefixes" }`.

- [ ] **Step 3: Run `go test ./internal/catalog/`. Expected: FAIL, because `Load` is undefined.**

- [ ] **Step 4: Implement `Load` and `Get`.** `Get` uses a map built in `Load`. Suffixes are stored lowercase without a trailing dot.

- [ ] **Step 5: Run `go test ./internal/catalog/`. Expected: PASS.**

- [ ] **Step 6: Commit** `feat: catalog loader for bots.yaml`

---

### Task 2: bots.yaml for the whole catalog

**Files:**
- Create: `bots.yaml`, `internal/catalog/bots_yaml_test.go`

**Interfaces:**
- Consumes: `catalog.Load` (Task 1). Formats are `google-prefixes` and `cidr-lines`, defined in Task 3. Until Task 3 lands, the test uses its own `knownFormats` with these two names.

- [ ] **Step 1: Write the failing test** `TestRepoBotsYAML`. It loads `../../bots.yaml`, expects no error, expects `len(Bots)` to equal the number of entries in goodbot-badbot's `app/bot_claims.json` (51 on 2026-11-17, a constant in the test with that comment), and checks that `googlebot`, `gptbot`, `claudebot`, `bingbot`, `ahrefsbot`, `ccbot` are `Checkable()` and `awario` is not.

- [ ] **Step 2: Run `go test ./internal/catalog/ -run RepoBots`. Expected: FAIL (file missing).**

- [ ] **Step 3: Write `bots.yaml`.** Take one entry per key in `~/Versioncontrol/local/goodbot-badbot/app/bot_claims.json`, with `id` set to the key, `name`, `ua_tokens` from `match`, and `docs` from the operator-docs `recognition` URL. Read `recognition` and map it as follows:
  - A published IP list becomes `ip_sources`. Fetch each URL once by hand. If the body has the shape `{"prefixes":[{"ipv4Prefix"|"ipv6Prefix":...}]}`, use `google-prefixes`. If it is one CIDR or IP per line, use `cidr-lines`. If it is neither, save it as `internal/sources/testdata/<id>.raw`, add a parser named `<operator>-json` in Task 3, and note it there.
  - "reverse DNS …" becomes `rdns_suffixes`, the domains taken from the operator's text.
  - Anything else becomes `not_checkable`, with the operator's statement or `"Operator publishes no IP list or reverse-DNS rule"`.

- [ ] **Step 4: Run the test. Expected: PASS.**

- [ ] **Step 5: Commit** `feat: bots.yaml derived from goodbot-badbot bot_claims.json`

---

### Task 3: Source parsers

**Files:**
- Create: `internal/sources/parse.go`, `internal/sources/parse_test.go`, `internal/sources/testdata/*.json|*.txt` (real bodies captured in Task 2, trimmed to a few prefixes)

**Interfaces:**
- Produces:
  - `type Parser func(body []byte) ([]netip.Prefix, error)`
  - `func ParserFor(format string) (Parser, bool)`
  - `func KnownFormat(format string) bool`
  - `var ErrNoPrefixes = errors.New("source contains no prefixes")`

- [ ] **Step 1: Write the failing tests**
  - `TestGooglePrefixes`: a fixture with `"ipv4Prefix":"66.249.64.0/27"` and `"ipv6Prefix":"2001:4860:4801:10::/64"` returns exactly those two prefixes.
  - `TestCIDRLines`: input `"# comment\n192.0.2.0/24\n\n198.51.100.7\n"` returns `192.0.2.0/24` and `198.51.100.7/32`.
  - `TestEmptyIsError` (Review Focus 2): `{"prefixes":[]}`, an empty body and `"<html>"` each return an error. The first two satisfy `errors.Is(err, ErrNoPrefixes)`.
  - `TestInvalidPrefixIsError`: `"ipv4Prefix":"999.1.1.1/8"` returns an error.
  - One test for each operator-specific parser added in Task 2, using its fixture.

- [ ] **Step 2: Run `go test ./internal/sources/`. Expected: FAIL.**

- [ ] **Step 3: Implement the parsers.** Use `netip.ParsePrefix`, and `netip.ParseAddr` plus `.Prefix(bits)` for single IPs. `Masked()` every prefix.

- [ ] **Step 4: Run `go test ./internal/sources/`. Expected: PASS.** Switch Task 2's test to `sources.KnownFormat`.

- [ ] **Step 5: Commit** `feat: parsers for operator IP-list formats`

---

### Task 4: Fetcher, store and refresh

**Files:**
- Create: `internal/sources/fetch.go`, `internal/sources/fetch_test.go`, `internal/store/store.go`, `internal/store/store_test.go`, `internal/store/refresh.go`, `internal/store/refresh_test.go`

**Interfaces:**
- Consumes: `catalog.Catalog`, `sources.ParserFor`
- Produces:
  - `type FetchState struct { ETag, LastModified string }`
  - `type FetchResult struct { Body []byte; NotModified bool; State FetchState }`
  - `func Fetch(ctx context.Context, client *http.Client, url string, prev FetchState) (FetchResult, error)`. It errors on any status other than 200 or 304 and on bodies over 5 MiB, and sends `User-Agent: bot-verify/<version> (+<repo url>)`.
  - `type Snapshot struct { Prefixes []netip.Prefix; FetchedAt time.Time; State sources.FetchState }`
  - `type Store struct` (an `RWMutex` and a `map[url]Snapshot`), `func New() *Store`, `func (s *Store) Get(url string) (Snapshot, bool)`, `func (s *Store) Set(url string, snap Snapshot)`
  - `func (s *Store) Contains(url string, ip netip.Addr) (matched bool, loaded bool, fetchedAt time.Time)`
  - `func Refresh(ctx context.Context, cat *catalog.Catalog, client *http.Client, s *Store, now func() time.Time) []error`. It fetches each distinct source URL once and returns one error per failed source, prefixed with the URL.
  - `func RunScheduler(ctx context.Context, interval time.Duration, refresh func(context.Context))`. It runs `refresh` immediately, then on every tick, and stops on `ctx.Done()`.

- [ ] **Step 1: Write the failing tests** (they use `httptest.Server`)
  - `TestFetchSendsConditionalHeaders`: with `prev{ETag:"\"a\""}` the server sees `If-None-Match: "a"` and answers 304, so the result has `NotModified==true`.
  - `TestFetchRejectsNon200` (status 500) and `TestFetchRejectsOversize` (a body of 5 MiB+1).
  - `TestRefreshKeepsLastGood` (Review Focus 2): the first refresh stores 1 prefix. The server then answers `{"prefixes":[]}` and the second refresh returns 1 error, while `Get(url)` still has 1 prefix and the old `FetchedAt`.
  - `TestRefreshNotModifiedBumpsFetchedAt`: a 304 keeps the prefixes and updates `FetchedAt` to `now()`.
  - `TestContainsNotLoaded`: on an empty store, `Contains` returns `loaded==false`.

- [ ] **Step 2: Run `go test ./internal/...`. Expected: FAIL.**

- [ ] **Step 3: Implement.** `Refresh` parses before it calls `Set`, so a failed parse never reaches the store.

- [ ] **Step 4: Run `go test -race ./internal/...`. Expected: PASS.**

- [ ] **Step 5: Commit** `feat: fetch operator sources with ETag and keep last good snapshot`

---

### Task 5: Forward-confirmed reverse DNS

**Files:**
- Create: `internal/rdns/rdns.go`, `internal/rdns/rdns_test.go`

**Interfaces:**
- Produces:
  - `type Resolver interface { LookupAddr(ctx context.Context, addr string) ([]string, error); LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) }` (`*net.Resolver` satisfies it)
  - `type Outcome int` with constants `Match`, `NoMatch`
  - `type Checker struct`, `func NewChecker(r Resolver, ttl time.Duration, maxConcurrent int, now func() time.Time) *Checker`
  - `func (c *Checker) Check(ctx context.Context, ip netip.Addr, suffixes []string) (Outcome, string, error)`. The string is the matching hostname. The error is non-nil only for transient failures.
  - `var ErrLookup = errors.New("dns lookup failed")`

- [ ] **Step 1: Write the failing tests** with a fake `Resolver` that counts calls.
  - `TestMatchForwardConfirmed`: PTR `crawl-66-249-66-1.googlebot.com.` with a forward lookup containing `66.249.66.1` gives `Match` and hostname `crawl-66-249-66-1.googlebot.com`.
  - `TestForwardMismatch`: the same PTR with a forward lookup returning only `203.0.113.9` gives `NoMatch`.
  - `TestSuffixBoundary` (Review Focus 3): PTR `evilgooglebot.com.` with suffix `googlebot.com` gives `NoMatch`, and no forward lookup is made. PTR `googlebot.com.` with the same suffix gives `Match`, because an exact match counts. `GoogleBot.COM.` matches case-insensitively.
  - `TestNXDOMAINIsNoMatch`: `&net.DNSError{IsNotFound:true}` gives `NoMatch` and a nil error.
  - `TestTransientIsErrorAndNotCached` (Review Focus 4): `&net.DNSError{IsTimeout:true}` gives `errors.Is(err, ErrLookup)`. A second call hits the resolver again.
  - `TestResultCached`: two `Match` calls within the TTL make one PTR lookup. After `now` passes the TTL, a new lookup is made.
  - `TestMultiplePTRs`: if any PTR passes both the suffix check and the forward check, the result is `Match`.

- [ ] **Step 2: Run `go test ./internal/rdns/`. Expected: FAIL.**

- [ ] **Step 3: Implement.** The cache key is `ip.String()+"|"+strings.Join(suffixes,",")`. A buffered channel of size `maxConcurrent` acts as a semaphore, and each lookup gets `context.WithTimeout` of 2s. Forward IPs are compared after `Unmap()`.

- [ ] **Step 4: Run `go test -race ./internal/rdns/`. Expected: PASS.**

- [ ] **Step 5: Commit** `feat: forward-confirmed reverse DNS checker with cache`

---

### Task 6: Verifier

**Files:**
- Create: `internal/verify/verify.go`, `internal/verify/verify_test.go`

**Interfaces:**
- Consumes: `catalog.Catalog`/`Bot`, `store.Store.Contains`, `rdns.Checker.Check` (behind a small interface `RDNS` so the tests can fake it)
- Produces:
  - `type Result struct { IP string \`json:"ip"\`; Bot string \`json:"bot"\`; Result string \`json:"result"\`; Method string \`json:"method"\`; Reason string \`json:"reason,omitempty"\`; Hostname string \`json:"hostname,omitempty"\`; Sources []string \`json:"sources"\`; DataAgeSeconds *int64 \`json:"data_age_seconds,omitempty"\` }`
  - `var ErrUnknownBot = errors.New("unknown bot")`
  - `func New(cat *catalog.Catalog, st *store.Store, r RDNS, now func() time.Time) *Verifier`
  - `func (v *Verifier) Verify(ctx context.Context, ip netip.Addr, botID string) (Result, error)`

Decision order. `Sources` always lists the bot's IP-source URLs plus its `Docs` URL.
1. The bot is unknown: return `ErrUnknownBot`.
2. `NotCheckable` is set: `not_checkable`, method `none`, reason = that text.
3. Any IP source contains the IP: `confirmed`, method `ip_list`, `DataAgeSeconds` from that snapshot.
4. There are RDNS suffixes and `Check` gives `Match`: `confirmed`, method `rdns`, with the hostname.
5. `Check` returned a transient error: `not_checkable`, method `rdns`, reason `dns lookup failed`.
6. One or more IP sources are not loaded and there are no RDNS suffixes: `not_checkable`, method `ip_list`, reason `source data not loaded`.
7. Otherwise `refuted`, with the method that was checked last.

- [ ] **Step 1: Write the failing tests**, one per rule above, named `TestVerify_<Rule>`, plus:
  - `TestVerifyUnmapsIPv4` (Review Focus 1): `::ffff:66.249.64.5` against a store holding `66.249.64.0/27` gives `confirmed` and `IP == "66.249.64.5"`.
  - `TestVerifyIPListBeforeRDNS`: when the IP list matches, the fake RDNS is not called.

- [ ] **Step 2: Run `go test ./internal/verify/`. Expected: FAIL.**

- [ ] **Step 3: Implement.** `Verify` calls `ip = ip.Unmap()` first.

- [ ] **Step 4: Run `go test ./internal/verify/`. Expected: PASS.**

- [ ] **Step 5: Commit** `feat: verifier combining IP lists and reverse DNS`

---

### Task 7: HTTP API

**Files:**
- Create: `internal/api/api.go`, `internal/api/api_test.go`

**Interfaces:**
- Consumes: `verify.Verifier`, `verify.Result`, `catalog.Catalog`, `store.Store`
- Produces: `func NewHandler(v *verify.Verifier, cat *catalog.Catalog, st *store.Store, logger *slog.Logger) http.Handler`

Endpoints (GET only, `application/json; charset=utf-8`, other methods return 405):
- `GET /v1/verify?ip=&bot=` returns 200 with a `verify.Result`. It returns 400 `{"error":{"code":"invalid_ip"|"invalid_bot","message":...}}` and 404 `{"error":{"code":"unknown_bot",...}}`.
- `GET /v1/bots` returns `[{"id","name","ua_tokens","checkable","methods":["ip_list","rdns"],"docs"}]`.
- `GET /v1/dataset` returns `{"generated_at", "bots":[{"id","rdns_suffixes","not_checkable","sources":[{"url","fetched_at","prefixes":[...]}]}]}`, the normalised dataset from spec decision 1.
- `GET /healthz` returns 200 `{"status":"ok","sources_loaded":n,"sources_total":m}`.
- Every response sets the headers `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`, `Cache-Control: public, max-age=300` (none on `/healthz`) and `Access-Control-Allow-Origin: *`.

- [ ] **Step 1: Write the failing tests** with `httptest`.
  - `TestVerifyOK`: a confirmed IP gives 200, and the body decodes to `result=="confirmed"`.
  - `TestVerifyBadInput`: `ip=foo` gives 400 `invalid_ip`. `bot=Google Bot` gives 400 `invalid_bot`. A missing parameter gives 400.
  - `TestVerifyUnknownBot`: 404 `unknown_bot`.
  - `TestMethodNotAllowed`: `POST /v1/verify` gives 405.
  - `TestSecurityHeaders`: each endpoint sets the headers above.
  - `TestLogsNoIP`: after a verify request, the slog buffer does not contain the queried IP.
  - `TestDatasetShape`: `/v1/dataset` contains the stored prefix as a string.

- [ ] **Step 2: Run `go test ./internal/api/`. Expected: FAIL.**

- [ ] **Step 3: Implement** with `http.ServeMux` method patterns (`"GET /v1/verify"`). Bot ids are validated with the same regex as Task 1, and IPs with `netip.ParseAddr`.

- [ ] **Step 4: Run `go test ./internal/api/`. Expected: PASS.**

- [ ] **Step 5: Commit** `feat: HTTP API for verify, bots, dataset, healthz`

---

### Task 8: Binary, container, docs

**Files:**
- Create: `cmd/bot-verify/main.go`, `cmd/bot-verify/main_test.go`, `Dockerfile`, `CHANGELOG.md`, `LICENSE` (ask the user which licence before you write it)
- Modify: `README.md`, `docs/idea.md` (set the status line to v1)

**Interfaces:**
- Consumes: everything above.
- Produces: the flags `-listen` (default `:8080`), `-bots` (default `bots.yaml`), `-refresh` (default `6h`), `-rdns-ttl` (default `15m`), `-rdns-concurrency` (default `64`), and `-version`.

- [ ] **Step 1: Write the failing test** `TestRunServesHealthz`. Start `run(ctx, args, stdout)` on `127.0.0.1:0` with the testdata catalog from Task 1 (one `httptest` source). Wait until `/healthz` reports `sources_loaded==1`, then cancel `ctx`. `run` returns nil within 5s.

- [ ] **Step 2: Run `go test ./cmd/...`. Expected: FAIL.**

- [ ] **Step 3: Implement `func run(ctx context.Context, args []string, stdout io.Writer) error`.** Wire `catalog.Load(…, sources.KnownFormat)`, `store.RunScheduler`, `rdns.NewChecker(net.DefaultResolver, …)`, `verify.New` and `api.NewHandler`. Shut down gracefully on SIGINT/SIGTERM through `signal.NotifyContext` in `main`. Use an `http.Server` with `ReadHeaderTimeout: 5s`, and an `http.Client` for fetches with `Timeout: 30s`.

- [ ] **Step 4: Run `go test -race ./...`. Expected: PASS.**

- [ ] **Step 5: Dockerfile.** Use a multi-stage build: `FROM golang:1.27 AS builder`, then `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=…"`. The final stage is `gcr.io/distroless/static-debian12:nonroot` with `bots.yaml` copied in, `USER nonroot`, and `EXPOSE 8080`. Distroless has no shell, so instead of a HEALTHCHECK, document that the orchestrator should probe `/healthz`. Verify with `docker build -t bot-verify . && docker run --rm -p 8080:8080 bot-verify` and `curl 'localhost:8080/v1/verify?ip=66.249.66.1&bot=googlebot'`. Expected: `"result":"confirmed"` once the first refresh is done.

- [ ] **Step 6: README.** Add usage, the API reference with one example per endpoint, how to add a bot to `bots.yaml`, and a **"Taking the client IP"** section. It says: use the address of the TCP peer, or of the one proxy hop you control. Never use the left-most `X-Forwarded-For` entry. With uvicorn, `--forwarded-allow-ips` must list only your proxy, never `"*"`. A verify answer for a forged IP is worse than no answer. Also note that the public instance should run behind a reverse proxy with per-client rate limiting.

- [ ] **Step 7: Commit** `feat: bot-verify binary, Dockerfile and docs`, then `CHANGELOG.md` with `## 0.1.0 – <date>`.

GitLab project, CI with Trivy and Renovate, and deployment of the public instance are not part of this plan. Do them afterwards with the `new-gitlab-project` and `gitlab-deploy` skills.
