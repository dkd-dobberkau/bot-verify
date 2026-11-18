package dnszone

import (
	"net/netip"
	"sync"
	"time"
)

// maxLimiterEntries bounds memory when many source addresses query. A full
// table drops only entries idle long enough to have refilled, which hold no
// state; spoofed new sources cannot push out a victim's exhausted bucket.
const maxLimiterEntries = 100_000

// sweepInterval caps how often a full table is scanned for idle entries, so
// a flood of new sources costs one scan per interval, not one per packet.
const sweepInterval = time.Second

// Limiter is a token bucket per IPv4 /24 and per IPv6 /56, as in response
// rate limiting of authoritative servers. It answers spoofed-source floods
// with truncated replies, so the server cannot be used to reflect traffic at
// a victim network, while honest resolvers retry over TCP.
type Limiter struct {
	mu        sync.Mutex
	rate      float64
	burst     float64
	buckets   map[netip.Addr]bucket
	lastSweep time.Time
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
		if len(l.buckets) >= maxLimiterEntries && !l.sweep(now) {
			// Every entry is active: a new source gets a truncated reply
			// and can still be answered over TCP.
			return false
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

// sweep removes entries idle long enough to be full again and reports
// whether there is room for a new one. It scans at most once per
// sweepInterval.
func (l *Limiter) sweep(now time.Time) bool {
	if now.Sub(l.lastSweep) < sweepInterval {
		return false
	}
	l.lastSweep = now
	refill := time.Duration(l.burst / l.rate * float64(time.Second))
	for key, b := range l.buckets {
		if now.Sub(b.last) >= refill {
			delete(l.buckets, key)
		}
	}
	return len(l.buckets) < maxLimiterEntries
}

func limiterKey(src netip.Addr) netip.Addr {
	src = src.Unmap()
	bits := 56
	if src.Is4() {
		bits = 24
	}
	prefix, _ := src.WithZone("").Prefix(bits)
	return prefix.Addr()
}
