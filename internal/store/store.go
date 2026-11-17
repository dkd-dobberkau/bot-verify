// Package store holds the last good copy of every operator IP list in memory
// and refreshes it on a schedule.
package store

import (
	"net/netip"
	"sync"
	"time"

	"bot-verify/internal/sources"
)

// Snapshot is the last successfully parsed content of one source URL.
type Snapshot struct {
	Prefixes  []netip.Prefix
	FetchedAt time.Time
	State     sources.FetchState
}

// Store maps source URLs to their snapshots. It is safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	snaps map[string]Snapshot
}

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
}

// Contains reports whether ip is in the source's prefixes, whether the
// source has been loaded at all, and when it was last fetched.
func (s *Store) Contains(url string, ip netip.Addr) (matched bool, loaded bool, fetchedAt time.Time) {
	snap, ok := s.Get(url)
	if !ok {
		return false, false, time.Time{}
	}
	for _, prefix := range snap.Prefixes {
		if prefix.Contains(ip) {
			return true, true, snap.FetchedAt
		}
	}
	return false, true, snap.FetchedAt
}
