# How a verdict is reached

`internal/verify/verify.go` decides. The steps run in this order, and the first
one that applies gives the answer:

1. **Unknown bot id**: HTTP 404 `unknown_bot`.
2. **Bot is `not_checkable` in `bots.yaml`**: `not_checkable`, method `none`,
   with the reason from the file.
3. **The IP is in any loaded IP list of the bot**: `confirmed`, method
   `ip_list`. Reverse DNS is not asked.
4. **The bot has reverse-DNS suffixes**, and the check is:
   - a DNS failure (timeout, SERVFAIL, the request deadline): `not_checkable`,
     method `rdns`, reason `dns lookup failed`;
   - a match: `confirmed`, method `rdns`, with the confirming `hostname`;
   - no match, with every IP list loaded: `refuted`, method `rdns`;
   - no match while a list is still missing or stale: go on to step 5.
5. **An IP list has not loaded yet**: `not_checkable`, method `ip_list`, reason
   `source data not loaded`. If every list is loaded but one is stale, the
   reason is `source data stale`.
6. **Otherwise**: `refuted`, method `ip_list`.

So `refuted` needs a definite answer from everything the operator offers.
Anything uncertain gives `not_checkable`, because a real crawler wrongly
refuted is the second-worst outcome, after a spoofer wrongly confirmed.

"Loaded" always means loaded and fresh: a list whose last successful fetch (or
304) is older than 7 days (`store.MaxAge`) counts as not loaded. It never
confirms and never refutes.

IPv4-mapped IPv6 addresses (`::ffff:66.249.66.1`) are treated as the IPv4 address.

## Reverse DNS (`internal/rdns`)

Forward-confirmed, as the operators describe it:

1. PTR lookup of the IP.
2. For each name: lowercased, trailing dot removed, it must equal a suffix or
   end in `.` + suffix. `evilgooglebot.com` does not match `googlebot.com`.
3. Forward lookup of that name, for the queried IP's family only (A for IPv4,
   AAAA for IPv6); the original IP must be among the results. Asking for one
   family keeps a failure of that family from hiding behind a "not found" of
   the other, which would otherwise turn a DNS outage into `refuted`.

Without step 3, anyone controlling the reverse zone of their own IP range could
claim any hostname.

| Limit | Value |
|---|---|
| Time for PTR and all forward lookups | 2 s |
| Time per verify request, including waiting for a lookup slot | 3 s |
| Concurrent checks | 64 (`-rdns-concurrency`) |
| Cache lifetime of definite answers | 15 min (`-rdns-ttl`) |
| Cache size | 100,000 entries, then cleared |

Failures are never cached, so the next request tries again. Concurrent checks
of the same IP and bot share one lookup and one slot.

## IP lists (`internal/sources`, `internal/store`)

- Fetched at start, then every 6 hours (`-refresh`), with `If-None-Match` and
  `If-Modified-Since`. Each distinct URL is fetched once, even when several
  bots share it.
- A fetch is rejected, and the **last good copy stays active**, when:
  - an `https://` source is redirected to anything but `https://` (the
    redirect is refused before the plain request is sent);
  - the connection would go to a non-public address (loopback, private,
    link-local, carrier-grade NAT, metadata endpoints), checked after DNS
    resolution so redirects and DNS rebinding are covered. With an outbound
    proxy configured (`HTTPS_PROXY`), the proxy owns this policy instead;
  - the status is not 200 or 304;
  - the body is larger than 5 MiB;
  - the body does not parse;
  - it lists no prefixes;
  - it contains a prefix broader than IPv4 /8 or IPv6 /16 (an operator
    mistake like `0.0.0.0/0` would otherwise confirm every IP).
- `data_age_seconds` in the answer says how old the list behind it is. There is
  no maximum age yet: a list stays in use however long refreshes fail (see
  [SECURITY.md](../SECURITY.md#known-limitations)).
