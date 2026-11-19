package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

func TestLimiterKeys(t *testing.T) {
	l := New(1, 1)
	at := time.Now()
	if !l.Allow(netip.MustParseAddr("2001:db8:0:1::1"), at) || l.Allow(netip.MustParseAddr("2001:db8:0:ff::2"), at) {
		t.Error("addresses in one IPv6 /56 must share a bucket")
	}
	if !l.Allow(netip.MustParseAddr("2001:db8:0:100::1"), at) {
		t.Error("another /56 must have its own bucket")
	}
	if !l.Allow(netip.MustParseAddr("192.0.2.1"), at) || l.Allow(netip.MustParseAddr("192.0.2.200"), at) {
		t.Error("addresses in one IPv4 /24 must share a bucket")
	}
	if !l.Allow(netip.MustParseAddr("192.0.3.1"), at) {
		t.Error("another IPv4 /24 must have its own bucket")
	}
	if l.Allow(netip.MustParseAddr("::ffff:192.0.2.1"), at) {
		t.Error("an IPv4-mapped address must share the IPv4 bucket")
	}
	if !l.Allow(netip.MustParseAddr("192.0.2.1"), at.Add(time.Second)) {
		t.Error("bucket did not refill after one second")
	}
}

// fillLimiter gives the table maxEntries distinct IPv6 /56 keys.
func fillLimiter(l *Limiter, at time.Time) {
	for i := range maxEntries {
		b := [16]byte{0x20, 0x01, 0x0d, 0xb9, byte(i >> 16), byte(i >> 8), byte(i)}
		l.Allow(netip.AddrFrom16(b), at)
	}
}

func TestLimiterKeepsExhaustedSourceWhenFull(t *testing.T) {
	l := New(1, 1)
	at := time.Now()
	victim := netip.MustParseAddr("192.0.2.1")
	if !l.Allow(victim, at) || l.Allow(victim, at) {
		t.Fatal("victim bucket not exhausted after its burst")
	}
	fillLimiter(l, at)
	if l.Allow(victim, at) {
		t.Error("a flood of new source keys restored the exhausted victim's burst")
	}
	if l.Allow(netip.MustParseAddr("198.51.100.1"), at) {
		t.Error("a new source was admitted while the table is full of active entries")
	}
}

func TestLimiterEvictsIdleEntriesWhenFull(t *testing.T) {
	l := New(1, 1)
	at := time.Now()
	fillLimiter(l, at)
	if !l.Allow(netip.MustParseAddr("198.51.100.1"), at.Add(2*time.Second)) {
		t.Error("a new source was refused although every entry had been idle long enough to refill")
	}
}
