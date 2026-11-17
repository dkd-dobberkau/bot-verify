package store

import (
	"net/netip"
	"testing"
	"time"
)

func TestContainsNotLoaded(t *testing.T) {
	s := New()
	matched, loaded, _ := s.Contains("https://a.example/x.json", netip.MustParseAddr("192.0.2.1"))
	if matched || loaded {
		t.Errorf("matched=%v loaded=%v, want both false", matched, loaded)
	}
}

func TestContainsMatch(t *testing.T) {
	s := New()
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	s.Set("u", Snapshot{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, FetchedAt: at})
	matched, loaded, fetchedAt := s.Contains("u", netip.MustParseAddr("192.0.2.9"))
	if !matched || !loaded || !fetchedAt.Equal(at) {
		t.Errorf("matched=%v loaded=%v fetchedAt=%v", matched, loaded, fetchedAt)
	}
	if matched, _, _ := s.Contains("u", netip.MustParseAddr("198.51.100.1")); matched {
		t.Error("matched an address outside the prefix")
	}
}
