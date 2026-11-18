// Package snapshot keeps the operator lists in a JSONL file, so a restart is
// ready at once instead of waiting for the first fetch of every source.
package snapshot

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/sources"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
)

// maxLineBytes fits one full source body (sources.MaxBodyBytes) re-encoded
// as a line.
const maxLineBytes = 6 << 20

// maxClockSkew is how far in the future a fetched_at may lie. A later one
// would keep a list fresh past store.MaxAge.
const maxClockSkew = time.Minute

// record is one source in the file.
type record struct {
	URL          string   `json:"url"`
	FetchedAt    string   `json:"fetched_at"`
	ETag         string   `json:"etag"`
	LastModified string   `json:"last_modified"`
	Prefixes     []string `json:"prefixes"`
}

// Write stores one line per catalog source the store holds. It writes a temp
// file in the same directory and renames it over path, so a crash leaves
// either the old or the new file, never half of one.
func Write(path string, cat *catalog.Catalog, st *store.Store) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".snapshot-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := writeLines(tmp, cat, st); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func writeLines(tmp *os.File, cat *catalog.Catalog, st *store.Store) error {
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetEscapeHTML(false)
	for _, url := range sourceURLs(cat) {
		snap, ok := st.Get(url)
		if !ok {
			continue
		}
		entry := record{URL: url, FetchedAt: snap.FetchedAt.UTC().Format(time.RFC3339),
			ETag: snap.State.ETag, LastModified: snap.State.LastModified,
			Prefixes: make([]string, 0, len(snap.Prefixes))}
		for _, prefix := range snap.Prefixes {
			entry.Prefixes = append(entry.Prefixes, prefix.String())
		}
		if err := encoder.Encode(entry); err != nil {
			return err
		}
	}
	return tmp.Sync()
}

// Load stores every valid line of path in st. A line is dropped with a
// warning if it is malformed, names a source not in the catalog, is older
// than store.MaxAge, or fails the parser's acceptance rules. Warnings name the
// URL and the reason, never prefixes. A missing file is not an error.
func Load(path string, cat *catalog.Catalog, st *store.Store, now time.Time) (loaded int, warnings []string, err error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	defer file.Close()

	known := make(map[string]bool)
	for _, url := range sourceURLs(cat) {
		known[url] = true
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	for n := 1; scanner.Scan(); n++ {
		if len(scanner.Bytes()) == 0 {
			continue
		}
		url, snap, reason := parseLine(scanner.Bytes(), known, now)
		if reason != "" {
			if url == "" {
				warnings = append(warnings, fmt.Sprintf("line %d: %s", n, reason))
			} else {
				warnings = append(warnings, fmt.Sprintf("%s: %s", url, reason))
			}
			continue
		}
		st.Set(url, snap)
		loaded++
	}
	return loaded, warnings, scanner.Err()
}

// parseLine returns the source URL (when it could be read) and its snapshot,
// or a reason the line is dropped. Reasons never quote prefixes.
func parseLine(raw []byte, known map[string]bool, now time.Time) (string, store.Snapshot, string) {
	var entry record
	if err := json.Unmarshal(raw, &entry); err != nil || entry.URL == "" {
		return "", store.Snapshot{}, "malformed line"
	}
	if !known[entry.URL] {
		return entry.URL, store.Snapshot{}, "source not in catalog"
	}
	fetchedAt, err := time.Parse(time.RFC3339, entry.FetchedAt)
	switch {
	case err != nil:
		return entry.URL, store.Snapshot{}, "invalid fetched_at"
	case now.Sub(fetchedAt) > store.MaxAge:
		return entry.URL, store.Snapshot{}, "older than the maximum list age"
	case fetchedAt.Sub(now) > maxClockSkew:
		return entry.URL, store.Snapshot{}, "fetched_at lies in the future"
	}
	prefixes := make([]netip.Prefix, 0, len(entry.Prefixes))
	for _, text := range entry.Prefixes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return entry.URL, store.Snapshot{}, "invalid prefix"
		}
		prefixes = append(prefixes, prefix)
	}
	prefixes, err = sources.ValidatePrefixes(prefixes)
	if err != nil {
		return entry.URL, store.Snapshot{}, "prefixes fail validation"
	}
	return entry.URL, store.Snapshot{Prefixes: prefixes, FetchedAt: fetchedAt,
		State: sources.FetchState{ETag: entry.ETag, LastModified: entry.LastModified}}, ""
}

// sourceURLs returns the catalog's distinct source URLs in catalog order.
func sourceURLs(cat *catalog.Catalog) []string {
	var out []string
	seen := make(map[string]bool)
	for _, bot := range cat.Bots {
		for _, src := range bot.IPSources {
			if !seen[src.URL] {
				seen[src.URL] = true
				out = append(out, src.URL)
			}
		}
	}
	return out
}

// Keep loads path into st, logging what it dropped, and returns the function
// to call after every refresh cycle: it writes the snapshot when the store
// changed since the last load or write. Write errors are logged, never
// fatal. With an empty path, snapshots are off and both steps do nothing.
func Keep(path string, cat *catalog.Catalog, st *store.Store, logger *slog.Logger) (afterRefresh func()) {
	if path == "" {
		return func() {}
	}
	loaded, warnings, err := Load(path, cat, st, time.Now())
	for _, warning := range warnings {
		logger.Warn("snapshot line dropped", "reason", warning)
	}
	if err != nil {
		logger.Warn("snapshot load failed", "error", err.Error())
	}
	logger.Info("snapshot loaded", "loaded", loaded, "dropped", len(warnings))
	written := st.Version()
	return func() {
		version := st.Version()
		if version == written {
			return
		}
		if err := Write(path, cat, st); err != nil {
			logger.Warn("snapshot write failed", "error", err.Error())
			return
		}
		written = version
	}
}
