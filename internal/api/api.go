// Package api serves verdicts, the bot list and the normalised dataset over HTTP.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
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
}

// NewHandler returns the API. It logs method, path, status and duration per
// request; never query parameters or client addresses.
func NewHandler(v *verify.Verifier, cat *catalog.Catalog, st *store.Store, logger *slog.Logger) http.Handler {
	h := &handler{verifier: v, catalog: cat, store: st}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/verify", h.verify)
	mux.HandleFunc("GET /v1/bots", h.bots)
	mux.HandleFunc("GET /v1/dataset", h.dataset)
	mux.HandleFunc("GET /healthz", h.healthz)
	return logRequests(logger, securityHeaders(mux))
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
	writeCachedJSON(w, map[string]any{"generated_at": time.Now().UTC(), "bots": bots})
}

func (h *handler) healthz(w http.ResponseWriter, _ *http.Request) {
	seen := make(map[string]bool)
	loaded := 0
	for _, bot := range h.catalog.Bots {
		for _, src := range bot.IPSources {
			if seen[src.URL] {
				continue
			}
			seen[src.URL] = true
			if _, ok := h.store.Get(src.URL); ok {
				loaded++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "sources_loaded": loaded, "sources_total": len(seen)})
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
	// Responses are JSON under a default-src 'none' CSP, never HTML, so
	// URLs keep a readable "&" instead of "&".
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.Encode(body)
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
		logger.Info("request", "method", r.Method, "path", r.URL.Path,
			"status", rec.status, "duration_ms", time.Since(start).Milliseconds())
	})
}
