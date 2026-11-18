package store

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
)

// sourceServer answers with the current body; an empty body means 304.
type sourceServer struct {
	body atomic.Value
	hits atomic.Int32
}

func (s *sourceServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	body := s.body.Load().(string)
	if body == "" {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", `"v1"`)
	w.Write([]byte(body))
}

func setup(t *testing.T, body string) (*sourceServer, *httptest.Server, *catalog.Catalog) {
	t.Helper()
	src := &sourceServer{}
	src.body.Store(body)
	srv := httptest.NewServer(src)
	t.Cleanup(srv.Close)
	cat := &catalog.Catalog{Bots: []catalog.Bot{
		{ID: "a", IPSources: []catalog.IPSource{{URL: srv.URL, Format: "google-prefixes"}}},
		{ID: "b", IPSources: []catalog.IPSource{{URL: srv.URL, Format: "google-prefixes"}}},
	}}
	return src, srv, cat
}

const onePrefix = `{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`

func TestRefreshFetchesEachURLOnce(t *testing.T) {
	src, srv, cat := setup(t, onePrefix)
	s := New()
	if errs := Refresh(context.Background(), cat, srv.Client(), s, time.Now); len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	if src.hits.Load() != 1 {
		t.Errorf("hits = %d, want 1", src.hits.Load())
	}
	if snap, ok := s.Get(srv.URL); !ok || len(snap.Prefixes) != 1 || snap.State.ETag != `"v1"` {
		t.Errorf("snapshot = %+v, %v", snap, ok)
	}
}

func TestRefreshKeepsLastGood(t *testing.T) {
	src, srv, cat := setup(t, onePrefix)
	s := New()
	first := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	Refresh(context.Background(), cat, srv.Client(), s, func() time.Time { return first })
	src.body.Store(`{"prefixes":[]}`)
	errs := Refresh(context.Background(), cat, srv.Client(), s, func() time.Time { return first.Add(6 * time.Hour) })
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), srv.URL) {
		t.Fatalf("errors = %v, want one naming the URL", errs)
	}
	snap, _ := s.Get(srv.URL)
	if len(snap.Prefixes) != 1 || !snap.FetchedAt.Equal(first) {
		t.Errorf("snapshot = %+v, want the first one kept", snap)
	}
}

func TestRefreshNotModifiedBumpsFetchedAt(t *testing.T) {
	src, srv, cat := setup(t, onePrefix)
	s := New()
	first := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	later := first.Add(6 * time.Hour)
	Refresh(context.Background(), cat, srv.Client(), s, func() time.Time { return first })
	src.body.Store("")
	if errs := Refresh(context.Background(), cat, srv.Client(), s, func() time.Time { return later }); len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	snap, _ := s.Get(srv.URL)
	if len(snap.Prefixes) != 1 || !snap.FetchedAt.Equal(later) {
		t.Errorf("snapshot = %+v, want prefixes kept and FetchedAt = later", snap)
	}
}

func TestRunSchedulerRunsImmediatelyAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		RunScheduler(ctx, time.Hour, func(context.Context) { runs.Add(1) })
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunScheduler did not stop")
	}
	if runs.Load() != 1 {
		t.Errorf("runs = %d, want 1", runs.Load())
	}
}

func TestRefreshMarksStoreRefreshed(t *testing.T) {
	_, srv, cat := setup(t, `{"prefixes":[]}`) // the source fails to parse
	s := New()
	if s.Refreshed() {
		t.Fatal("new store reports refreshed")
	}
	Refresh(context.Background(), cat, srv.Client(), s, time.Now)
	if !s.Refreshed() {
		t.Error("store not marked refreshed after a completed refresh cycle, even a failed one")
	}
}
