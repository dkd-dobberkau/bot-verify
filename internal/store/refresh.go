package store

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/sources"
)

// Refresh fetches every distinct source URL in the catalog once. A source
// that fails to fetch or parse keeps its previous snapshot; the failure is
// returned, prefixed with the URL.
func Refresh(ctx context.Context, cat *catalog.Catalog, client *http.Client, s *Store, now func() time.Time) []error {
	var errs []error
	seen := make(map[string]bool)
	for _, bot := range cat.Bots {
		for _, src := range bot.IPSources {
			if seen[src.URL] {
				continue
			}
			seen[src.URL] = true
			if err := refreshOne(ctx, client, s, src, now); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", src.URL, err))
			}
		}
	}
	s.refreshed.Store(true)
	return errs
}

func refreshOne(ctx context.Context, client *http.Client, s *Store, src catalog.IPSource, now func() time.Time) error {
	prev, _ := s.Get(src.URL)
	res, err := sources.Fetch(ctx, client, src.URL, prev.State)
	if err != nil {
		return err
	}
	if res.NotModified {
		if prev.Prefixes == nil {
			return fmt.Errorf("304 without a stored copy")
		}
		prev.FetchedAt = now()
		s.Set(src.URL, prev)
		return nil
	}
	parse, ok := sources.ParserFor(src.Format)
	if !ok {
		return fmt.Errorf("unknown format %q", src.Format)
	}
	prefixes, err := parse(res.Body)
	if err != nil {
		return err
	}
	s.Set(src.URL, Snapshot{Prefixes: prefixes, FetchedAt: now(), State: res.State})
	return nil
}

// RunScheduler calls refresh immediately and then every interval until ctx ends.
func RunScheduler(ctx context.Context, interval time.Duration, refresh func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
