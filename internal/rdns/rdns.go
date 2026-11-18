// Package rdns verifies a bot's reverse-DNS claim the way operators describe
// it: PTR lookup, suffix match, then a forward lookup that must return the
// same IP. Without the forward step anyone controlling a PTR zone could pass.
package rdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// ErrLookup means DNS did not give an answer (timeout, SERVFAIL). It is never
// a reason to call a claim refuted.
var ErrLookup = errors.New("dns lookup failed")

const (
	lookupTimeout = 2 * time.Second
	// maxCacheEntries bounds memory when many distinct IPs are queried; the
	// cache is dropped wholesale when it fills, which only costs lookups.
	maxCacheEntries = 100_000
)

// Resolver is the part of *net.Resolver the checker uses.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Outcome is a definite DNS answer.
type Outcome int

const (
	NoMatch Outcome = iota
	Match
)

func (o Outcome) String() string {
	if o == Match {
		return "Match"
	}
	return "NoMatch"
}

type cacheEntry struct {
	outcome  Outcome
	hostname string
	expires  time.Time
}

// flight is a lookup in progress; concurrent checks of the same key wait for it.
type flight struct {
	done     chan struct{}
	outcome  Outcome
	hostname string
	err      error
}

// Checker runs forward-confirmed reverse-DNS checks with a result cache, a cap
// on concurrent lookups, and one shared lookup per key at a time.
type Checker struct {
	resolver Resolver
	ttl      time.Duration
	slots    chan struct{}
	now      func() time.Time

	mu       sync.Mutex
	cache    map[string]cacheEntry
	inflight map[string]*flight
}

// NewChecker returns a checker. Definite answers are cached for ttl;
// lookup failures are not cached.
func NewChecker(r Resolver, ttl time.Duration, maxConcurrent int, now func() time.Time) *Checker {
	return &Checker{
		resolver: r,
		ttl:      ttl,
		slots:    make(chan struct{}, maxConcurrent),
		now:      now,
		cache:    make(map[string]cacheEntry),
		inflight: make(map[string]*flight),
	}
}

// Check reports whether ip has a PTR name under one of suffixes that resolves
// back to ip. The hostname returned is the confirming name without trailing
// dot. A non-nil error wraps ErrLookup.
func (c *Checker) Check(ctx context.Context, ip netip.Addr, suffixes []string) (Outcome, string, error) {
	ip = ip.Unmap()
	key := ip.String() + "|" + strings.Join(suffixes, ",")
	if entry, ok := c.cached(key); ok {
		return entry.outcome, entry.hostname, nil
	}
	c.mu.Lock()
	if f, ok := c.inflight[key]; ok {
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.outcome, f.hostname, f.err
		case <-ctx.Done():
			return NoMatch, "", errors.Join(ErrLookup, ctx.Err())
		}
	}
	f := &flight{done: make(chan struct{})}
	c.inflight[key] = f
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.inflight, key)
		c.mu.Unlock()
		close(f.done)
	}()
	f.outcome, f.hostname, f.err = c.checkUncached(ctx, ip, suffixes, key)
	return f.outcome, f.hostname, f.err
}

// checkUncached takes a lookup slot, runs the lookup and caches a definite answer.
func (c *Checker) checkUncached(ctx context.Context, ip netip.Addr, suffixes []string, key string) (Outcome, string, error) {
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return NoMatch, "", errors.Join(ErrLookup, ctx.Err())
	}
	outcome, hostname, err := c.lookup(ctx, ip, suffixes)
	if err != nil {
		return NoMatch, "", err
	}
	c.store(key, cacheEntry{outcome: outcome, hostname: hostname, expires: c.now().Add(c.ttl)})
	return outcome, hostname, nil
}

func (c *Checker) lookup(ctx context.Context, ip netip.Addr, suffixes []string) (Outcome, string, error) {
	ctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	names, err := c.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		if isNotFound(err) {
			return NoMatch, "", nil
		}
		return NoMatch, "", errors.Join(ErrLookup, err)
	}
	// Ask only for the queried IP's address family. A merged A+AAAA lookup
	// reports "not found" from one family even when the other failed
	// transiently, which would turn a DNS outage into a definite no.
	network := "ip6"
	if ip.Is4() {
		network = "ip4"
	}
	var transient error
	for _, name := range names {
		host := strings.ToLower(strings.TrimSuffix(name, "."))
		if !hasSuffix(host, suffixes) {
			continue
		}
		addrs, err := c.resolver.LookupNetIP(ctx, network, name)
		if err != nil {
			if !isNotFound(err) {
				transient = err
			}
			continue
		}
		for _, forward := range addrs {
			if forward.Unmap() == ip {
				return Match, host, nil
			}
		}
	}
	if transient != nil {
		return NoMatch, "", errors.Join(ErrLookup, transient)
	}
	return NoMatch, "", nil
}

// hasSuffix matches whole labels: "a.googlebot.com" and "googlebot.com" match
// "googlebot.com", "evilgooglebot.com" does not.
func hasSuffix(host string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func (c *Checker) cached(key string) (cacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.cache[key]
	if !ok || !c.now().Before(entry.expires) {
		return cacheEntry{}, false
	}
	return entry, true
}

func (c *Checker) store(key string, entry cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= maxCacheEntries {
		c.cache = make(map[string]cacheEntry)
	}
	c.cache[key] = entry
}
