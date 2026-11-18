package snapshot

import (
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/sources"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
)

const (
	urlA = "https://a.example/list.json"
	urlB = "https://b.example/list.txt"
)

var now = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func testCatalog() *catalog.Catalog {
	return catalog.New([]catalog.Bot{
		{ID: "abot", Name: "ABot", IPSources: []catalog.IPSource{{URL: urlA, Format: "google-prefixes"}}},
		{ID: "bbot", Name: "BBot", IPSources: []catalog.IPSource{{URL: urlB, Format: "cidr-lines"}, {URL: urlA, Format: "google-prefixes"}}},
		{ID: "nobot", Name: "NoBot", NotCheckable: "nothing published"},
	})
}

func prefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func filledStore() *store.Store {
	st := store.New()
	st.Set(urlA, store.Snapshot{
		Prefixes:  prefixes("66.249.64.0/27", "2001:4860:4801:10::/64"),
		FetchedAt: now.Add(-time.Hour).Add(250 * time.Millisecond),
		State:     sources.FetchState{ETag: `"abc"`, LastModified: "Tue, 17 Nov 2026 10:00:00 GMT"},
	})
	st.Set(urlB, store.Snapshot{
		Prefixes:  prefixes("192.0.2.0/24"),
		FetchedAt: now.Add(-48 * time.Hour),
	})
	return st
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	src := filledStore()
	if err := Write(path, testCatalog(), src); err != nil {
		t.Fatalf("Write: %v", err)
	}
	dst := store.New()
	loaded, warnings, err := Load(path, testCatalog(), dst, now)
	if err != nil || loaded != 2 || len(warnings) != 0 {
		t.Fatalf("Load = %d, %v, %v; want 2, no warnings, nil", loaded, warnings, err)
	}
	for _, url := range []string{urlA, urlB} {
		want, _ := src.Get(url)
		got, ok := dst.Get(url)
		if !ok {
			t.Fatalf("%s not loaded", url)
		}
		if !reflect.DeepEqual(got.Prefixes, want.Prefixes) || got.State != want.State {
			t.Errorf("%s: got %+v, want %+v", url, got, want)
		}
		if !got.FetchedAt.Equal(want.FetchedAt.Truncate(time.Second)) {
			t.Errorf("%s: FetchedAt = %v, want %v to the second", url, got.FetchedAt, want.FetchedAt)
		}
	}
}

func line(t *testing.T, url string, fetchedAt time.Time, prefixes ...string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"url": url, "fetched_at": fetchedAt.Format(time.RFC3339),
		"etag": "", "last_modified": "", "prefixes": prefixes})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoadDropsBadLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	lines := []string{
		line(t, urlA, now.Add(-time.Hour), "66.249.64.0/27"),
		`{"url": "` + urlB + `", "prefixes": [`,
		line(t, "https://gone.example/list.json", now.Add(-time.Hour), "198.51.100.0/24"),
		line(t, urlB, now.Add(-store.MaxAge-time.Second), "203.0.113.0/24"),
		line(t, urlB, now.Add(-time.Hour), "0.0.0.0/0"),
		line(t, urlB, now.Add(time.Hour), "203.0.113.0/24"),
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := store.New()
	loaded, warnings, err := Load(path, testCatalog(), st, now)
	if err != nil || loaded != 1 {
		t.Fatalf("Load = %d, %v, %v; want 1 loaded", loaded, warnings, err)
	}
	if len(warnings) != 5 {
		t.Errorf("warnings = %q, want 5", warnings)
	}
	for _, w := range warnings {
		for _, p := range []string{"66.249", "198.51.100", "203.0.113", "0.0.0.0"} {
			if strings.Contains(w, p) {
				t.Errorf("warning %q contains prefix text %q", w, p)
			}
		}
	}
	if _, ok := st.Get(urlB); ok {
		t.Error("an invalid line for urlB reached the store")
	}
}

func TestWriteIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	if err := Write(path, testCatalog(), filledStore()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != "s.jsonl" {
		t.Errorf("directory holds %v, want only s.jsonl", entries)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v; want 0600", info.Mode().Perm(), err)
	}
	before, _ := os.ReadFile(path)

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	changed := store.New()
	changed.Set(urlA, store.Snapshot{Prefixes: prefixes("10.0.0.0/8"), FetchedAt: now})
	if err := Write(path, testCatalog(), changed); err == nil {
		t.Error("Write into a read-only directory returned nil")
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("previous snapshot changed after a failed Write")
	}
	os.Chmod(dir, 0o700)

	stray := line(t, urlB, now, "203.0.113.0/24")
	if err := os.WriteFile(filepath.Join(dir, ".s.jsonl-123.tmp"), []byte(stray+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st := store.New()
	if _, _, err := Load(path, testCatalog(), st, now); err != nil {
		t.Fatal(err)
	}
	if snap, _ := st.Get(urlB); reflect.DeepEqual(snap.Prefixes, prefixes("203.0.113.0/24")) {
		t.Error("Load read the stray temp file")
	}
}

func TestLoadMissingFile(t *testing.T) {
	loaded, warnings, err := Load(filepath.Join(t.TempDir(), "none.jsonl"), testCatalog(), store.New(), now)
	if loaded != 0 || warnings != nil || err != nil {
		t.Errorf("Load = %d, %v, %v; want 0, nil, nil", loaded, warnings, err)
	}
}

func TestKeepWritesOnlyWhenStoreChanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	src := store.New() // Keep checks the age against the wall clock
	src.Set(urlA, store.Snapshot{Prefixes: prefixes("66.249.64.0/27"), FetchedAt: time.Now().Add(-time.Hour)})
	src.Set(urlB, store.Snapshot{Prefixes: prefixes("192.0.2.0/24"), FetchedAt: time.Now().Add(-time.Hour)})
	if err := Write(path, testCatalog(), src); err != nil {
		t.Fatal(err)
	}
	st := store.New()
	logs := &strings.Builder{}
	afterRefresh := Keep(path, testCatalog(), st, slog.New(slog.NewTextHandler(logs, nil)))
	if _, ok := st.Get(urlA); !ok {
		t.Fatal("Keep did not load the snapshot")
	}
	if !strings.Contains(logs.String(), "loaded=2") {
		t.Errorf("logs = %q, want a line with loaded=2", logs.String())
	}

	os.Remove(path)
	afterRefresh()
	if _, err := os.Stat(path); err == nil {
		t.Error("written although the store did not change since loading")
	}
	st.Set(urlB, store.Snapshot{Prefixes: prefixes("203.0.113.0/24"), FetchedAt: time.Now()})
	afterRefresh()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("not written after the store changed: %v", err)
	}
}

func TestKeepWithoutPathIsOff(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	st := filledStore()
	Keep("", testCatalog(), st, slog.New(slog.DiscardHandler))()
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("files written with snapshots off: %v", entries)
	}
}

func TestKeepRemovesOwnLeftoverTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	own := filepath.Join(dir, ".s.jsonl-123.tmp")
	other := filepath.Join(dir, ".other.jsonl-456.tmp")
	for _, f := range []string{own, other} {
		if err := os.WriteFile(f, []byte("partial"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	Keep(path, testCatalog(), store.New(), slog.New(slog.DiscardHandler))
	if _, err := os.Stat(own); err == nil {
		t.Error("leftover temp file of this snapshot was not removed")
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("temp file of another snapshot in the same directory was removed")
	}
}

func TestWriteTempFileIsNamedAfterSnapshot(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	err := Write(filepath.Join(dir, "s.jsonl"), testCatalog(), filledStore())
	if err == nil || !strings.Contains(err.Error(), ".s.jsonl-") {
		t.Errorf("Write error = %v, want one naming the temp pattern .s.jsonl-*.tmp", err)
	}
}
