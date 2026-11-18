// Package store holds the last good copy of every operator IP list in memory
// and refreshes it on a schedule.
package store

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/sources"
)

// Snapshot is the last successfully parsed content of one source URL.
type Snapshot struct {
	Prefixes  []netip.Prefix
	FetchedAt time.Time
	State     sources.FetchState
}

// Store maps source URLs to their snapshots. It is safe for concurrent use.
type Store struct {
	mu        sync.RWMutex
	snaps     map[string]Snapshot
	refreshed atomic.Bool
	version   atomic.Uint64
}

// Version changes whenever a snapshot is replaced.
func (s *Store) Version() uint64 { return s.version.Load() }

// Refreshed reports whether at least one refresh cycle has completed.
func (s *Store) Refreshed() bool { return s.refreshed.Load() }

// New returns an empty store.
func New() *Store {
	return &Store{snaps: make(map[string]Snapshot)}
}

// Get returns the snapshot for a source URL.
func (s *Store) Get(url string) (Snapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap, ok := s.snaps[url]
	return snap, ok
}

// Set replaces the snapshot for a source URL.
func (s *Store) Set(url string, snap Snapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snaps[url] = snap
	s.version.Add(1)
}

// MaxAge is how long a list stays usable after its last successful fetch or
// 304. An operator list that cannot be refreshed for longer may have moved
// addresses to someone else, so it must not confirm or refute anymore.
const MaxAge = 7 * 24 * time.Hour

// ListState is whether a source's list can be used for a verdict.
type ListState int

const (
	NotLoaded ListState = iota
	Stale
	Loaded
)

// State reports whether the source is loaded and fresh at now.
func (s *Store) State(url string, now time.Time) ListState {
	snap, ok := s.Get(url)
	return stateOf(snap, ok, now)
}

// Lookup reports the source's state, whether ip is in its prefixes, and when
// it was last fetched. matched is only ever true for a Loaded list.
func (s *Store) Lookup(url string, ip netip.Addr, now time.Time) (state ListState, matched bool, fetchedAt time.Time) {
	snap, ok := s.Get(url)
	state = stateOf(snap, ok, now)
	if state != Loaded {
		return state, false, snap.FetchedAt
	}
	for _, prefix := range snap.Prefixes {
		if prefix.Contains(ip) {
			return state, true, snap.FetchedAt
		}
	}
	return state, false, snap.FetchedAt
}

func stateOf(snap Snapshot, ok bool, now time.Time) ListState {
	switch {
	case !ok:
		return NotLoaded
	case now.Sub(snap.FetchedAt) > MaxAge:
		return Stale
	default:
		return Loaded
	}
}
