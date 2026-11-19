// Package ratelimit is a token bucket per source network, shared by the HTTP
// API and the DNS zone.
package ratelimit

import (
	"net/netip"
	"sync"
	"time"
)

// maxEntries bounds memory when many source addresses query. A full table
// drops only entries idle long enough to have refilled, which hold no state;
// new sources, spoofed or not, cannot push out a victim's exhausted bucket.
const maxEntries = 100_000

// sweepInterval caps how often a full table is scanned for idle entries, so
// a flood of new sources costs one scan per interval, not one per packet.
const sweepInterval = time.Second

// Limiter is a token bucket per IPv4 /24 and per IPv6 /56, as in response
// rate limiting of authoritative servers: a single host easily holds many
// addresses of its /24 or /56, so a bucket per address would not limit it.
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

// New allows ratePerSecond requests per key, with bursts up to burst.
func New(ratePerSecond, burst int) *Limiter {
	return &Limiter{rate: float64(ratePerSecond), burst: float64(burst), buckets: make(map[netip.Addr]bucket)}
}

// Allow takes one token from src's bucket.
func (l *Limiter) Allow(src netip.Addr, now time.Time) bool {
	key := Key(src)
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxEntries && !l.sweep(now) {
			// Every entry is active, so a new source is refused too.
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
	return len(l.buckets) < maxEntries
}

// Key is the network a source address is counted under: its IPv4 /24 or
// IPv6 /56. An IPv4-mapped address counts as IPv4.
func Key(src netip.Addr) netip.Addr {
	src = src.Unmap()
	bits := 56
	if src.Is4() {
		bits = 24
	}
	prefix, _ := src.WithZone("").Prefix(bits)
	return prefix.Addr()
}
