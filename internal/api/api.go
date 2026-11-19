// Package api serves verdicts, the bot list and the normalised dataset over HTTP.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
	"github.com/dkd-dobberkau/bot-verify/internal/verify"
)

// verifyTimeout bounds one verification, including the wait for a free
// reverse-DNS slot; without it a flood of slow reverse zones starves everyone.
var verifyTimeout = 3 * time.Second

type handler struct {
	verifier *verify.Verifier
	catalog  *catalog.Catalog
	store    *store.Store

	// The dataset is rebuilt only when the store changes.
	datasetMu      sync.Mutex
	datasetVersion uint64
	datasetBody    []byte
}

// NewHandler returns the API. It logs method, matched route, status and duration per
// request; never query parameters or client addresses.
func NewHandler(v *verify.Verifier, cat *catalog.Catalog, st *store.Store, logger *slog.Logger, limit ClientLimit) http.Handler {
	h := &handler{verifier: v, catalog: cat, store: st}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/verify", h.verify)
	mux.HandleFunc("GET /v1/bots", h.bots)
	mux.HandleFunc("GET /v1/dataset", h.dataset)
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
	mux.HandleFunc("GET /{$}", home)
	mux.HandleFunc("GET /robots.txt", robots)
	return logRequests(logger, securityHeaders(limitClients(limit, mux)))
}

func (h *handler) verify(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	ip, err := netip.ParseAddr(query.Get("ip"))
	if err != nil || ip.Zone() != "" {
		writeError(w, http.StatusBadRequest, "invalid_ip", "ip must be an IPv4 or IPv6 address")
		return
	}
	botID := query.Get("bot")
	if !catalog.IDPattern.MatchString(botID) {
		writeError(w, http.StatusBadRequest, "invalid_bot", "bot must be a bot id as listed by /v1/bots")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), verifyTimeout)
	defer cancel()
	res, err := h.verifier.Verify(ctx, ip, botID)
	if errors.Is(err, verify.ErrUnknownBot) {
		writeError(w, http.StatusNotFound, "unknown_bot", "no bot with this id; see /v1/bots")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "verification failed")
		return
	}
	writeCachedJSON(w, res)
}

type botInfo struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	UATokens  []string `json:"ua_tokens"`
	Checkable bool     `json:"checkable"`
	Methods   []string `json:"methods"`
	Docs      string   `json:"docs,omitempty"`
}

func (h *handler) bots(w http.ResponseWriter, _ *http.Request) {
	out := make([]botInfo, 0, len(h.catalog.Bots))
	for _, bot := range h.catalog.Bots {
		methods := []string{}
		if len(bot.IPSources) > 0 {
			methods = append(methods, verify.MethodIPList)
		}
		if len(bot.RDNSSuffixes) > 0 {
			methods = append(methods, verify.MethodRDNS)
		}
		out = append(out, botInfo{ID: bot.ID, Name: bot.Name, UATokens: bot.UATokens,
			Checkable: bot.Checkable(), Methods: methods, Docs: bot.Docs})
	}
	writeCachedJSON(w, out)
}

type datasetSource struct {
	URL       string     `json:"url"`
	FetchedAt *time.Time `json:"fetched_at"`
	Prefixes  []string   `json:"prefixes"`
}

type datasetBot struct {
	ID           string          `json:"id"`
	RDNSSuffixes []string        `json:"rdns_suffixes,omitempty"`
	NotCheckable string          `json:"not_checkable,omitempty"`
	Sources      []datasetSource `json:"sources,omitempty"`
}

func (h *handler) dataset(w http.ResponseWriter, _ *http.Request) {
	h.datasetMu.Lock()
	if version := h.store.Version(); h.datasetBody == nil || version != h.datasetVersion {
		h.datasetBody, h.datasetVersion = h.buildDataset(), version
	}
	body := h.datasetBody
	h.datasetMu.Unlock()
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(body)
}

func (h *handler) buildDataset() []byte {
	bots := make([]datasetBot, 0, len(h.catalog.Bots))
	for _, bot := range h.catalog.Bots {
		entry := datasetBot{ID: bot.ID, RDNSSuffixes: bot.RDNSSuffixes, NotCheckable: bot.NotCheckable}
		for _, src := range bot.IPSources {
			ds := datasetSource{URL: src.URL, Prefixes: []string{}}
			if snap, ok := h.store.Get(src.URL); ok {
				fetchedAt := snap.FetchedAt.UTC()
				ds.FetchedAt = &fetchedAt
				for _, prefix := range snap.Prefixes {
					ds.Prefixes = append(ds.Prefixes, prefix.String())
				}
			}
			entry.Sources = append(entry.Sources, ds)
		}
		bots = append(bots, entry)
	}
	return encodeJSON(map[string]any{"generated_at": time.Now().UTC(), "bots": bots})
}

// sourceCounts returns how many distinct source URLs are loaded and fresh,
// of how many.
func (h *handler) sourceCounts() (loaded, total int) {
	seen := make(map[string]bool)
	now := time.Now()
	for _, bot := range h.catalog.Bots {
		for _, src := range bot.IPSources {
			if seen[src.URL] {
				continue
			}
			seen[src.URL] = true
			if h.store.State(src.URL, now) == store.Loaded {
				loaded++
			}
		}
	}
	return loaded, len(seen)
}

// healthz is liveness: the process serves requests.
func (h *handler) healthz(w http.ResponseWriter, _ *http.Request) {
	loaded, total := h.sourceCounts()
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "sources_loaded": loaded, "sources_total": total})
}

// readyz is readiness: at least one IP list is loaded and fresh, which a
// snapshot can give before the first refresh cycle. A catalog without
// sources is ready once a cycle has run. Until then, list-only bots get
// not_checkable.
func (h *handler) readyz(w http.ResponseWriter, _ *http.Request) {
	loaded, total := h.sourceCounts()
	status, code := "ready", http.StatusOK
	switch {
	case loaded > 0, total == 0 && h.store.Refreshed():
	case !h.store.Refreshed():
		status, code = "starting", http.StatusServiceUnavailable
	default:
		status, code = "no_sources_loaded", http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"status": status, "sources_loaded": loaded, "sources_total": total})
}

func writeCachedJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(encodeJSON(body))
}

// encodeJSON does not HTML-escape: responses are JSON under a default-src
// 'none' CSP, never HTML, so URLs keep a readable "&" instead of a Unicode escape.
func encodeJSON(body any) []byte {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.Encode(body)
	return buf.Bytes()
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Security-Policy", "default-src 'none'")
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(status int) {
	s.status = status
	s.ResponseWriter.WriteHeader(status)
}

func logRequests(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// The matched route, not the path: a path is client input and may
		// hold an address. The mux sets Pattern on r; unmatched stays empty.
		logger.Info("request", "method", r.Method, "route", r.Pattern,
			"status", rec.status, "duration_ms", time.Since(start).Milliseconds())
	})
}
