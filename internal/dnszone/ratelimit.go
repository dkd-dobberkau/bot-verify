package dnszone

import (
	"net/netip"
	"sync"
	"time"
)

// maxLimiterEntries bounds memory when many source addresses query; the
// table is dropped wholesale when it fills, which only resets the limits.
const maxLimiterEntries = 100_000

// Limiter is a token bucket per IPv4 address and per IPv6 /56. It answers
// spoofed-source floods with truncated replies, so the server cannot be used
// to reflect traffic at a victim, while honest resolvers retry over TCP.
type Limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[netip.Addr]bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter allows ratePerSecond queries per key, with bursts up to burst.
func NewLimiter(ratePerSecond, burst int) *Limiter {
	return &Limiter{rate: float64(ratePerSecond), burst: float64(burst), buckets: make(map[netip.Addr]bucket)}
}

// Allow takes one token from src's bucket.
func (l *Limiter) Allow(src netip.Addr, now time.Time) bool {
	key := limiterKey(src)
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxLimiterEntries {
			l.buckets = make(map[netip.Addr]bucket)
		}
		b = bucket{tokens: l.burst, last: now}
	}
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
		b.last = now
	}
	allowed := b.tokens >= 1
	if allowed {
		b.tokens--
	}
	l.buckets[key] = b
	return allowed
}

func limiterKey(src netip.Addr) netip.Addr {
	src = src.Unmap()
	if src.Is4() {
		return src
	}
	prefix, _ := src.WithZone("").Prefix(56)
	return prefix.Addr()
}
