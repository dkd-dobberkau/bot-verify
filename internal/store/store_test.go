package store

import (
	"net/netip"
	"testing"
	"time"
)

func TestLookupStates(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	inside := netip.MustParseAddr("192.0.2.9")
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	s := New()

	if state, matched, _ := s.Lookup("unset", inside, now); state != NotLoaded || matched {
		t.Errorf("unset: state=%v matched=%v, want NotLoaded false", state, matched)
	}

	edge := now.Add(-MaxAge)
	s.Set("edge", Snapshot{Prefixes: prefixes, FetchedAt: edge})
	state, matched, fetchedAt := s.Lookup("edge", inside, now)
	if state != Loaded || !matched || !fetchedAt.Equal(edge) {
		t.Errorf("exactly MaxAge old: state=%v matched=%v fetchedAt=%v, want Loaded true %v", state, matched, fetchedAt, edge)
	}
	if _, matched, _ := s.Lookup("edge", netip.MustParseAddr("198.51.100.1"), now); matched {
		t.Error("matched an address outside the prefix")
	}
	if got := s.State("edge", now); got != Loaded {
		t.Errorf("State(edge) = %v, want Loaded", got)
	}

	s.Set("stale", Snapshot{Prefixes: prefixes, FetchedAt: now.Add(-MaxAge - time.Second)})
	if state, matched, _ := s.Lookup("stale", inside, now); state != Stale || matched {
		t.Errorf("one second past MaxAge: state=%v matched=%v, want Stale false", state, matched)
	}
	if got := s.State("stale", now); got != Stale {
		t.Errorf("State(stale) = %v, want Stale", got)
	}
	if got := s.State("unset", now); got != NotLoaded {
		t.Errorf("State(unset) = %v, want NotLoaded", got)
	}
}
