package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/rdns"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
	"github.com/dkd-dobberkau/bot-verify/internal/verify"
)

type noRDNS struct{}

func (noRDNS) Check(context.Context, netip.Addr, []string) (rdns.Outcome, string, error) {
	return rdns.NoMatch, "", nil
}

const listURL = "https://ops.example/list.json"

func newServer(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	cat := catalog.New([]catalog.Bot{
		{ID: "listbot", Name: "ListBot", UATokens: []string{"ListBot"},
			IPSources: []catalog.IPSource{{URL: listURL, Format: "google-prefixes"}}, Docs: "https://ops.example/bots"},
		{ID: "nobot", Name: "NoBot", NotCheckable: "nothing published"},
	})
	st := store.New()
	st.Set(listURL, store.Snapshot{Prefixes: []netip.Prefix{netip.MustParsePrefix("66.249.64.0/27")}, FetchedAt: time.Now()})
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	srv := httptest.NewServer(NewHandler(verify.New(cat, st, noRDNS{}, time.Now), cat, st, logger))
	t.Cleanup(srv.Close)
	return srv, logs
}

func get(t *testing.T, srv *httptest.Server, path string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	return resp, body
}

func errorCode(body map[string]any) string {
	e, _ := body["error"].(map[string]any)
	code, _ := e["code"].(string)
	return code
}

func TestVerifyOK(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := get(t, srv, "/v1/verify?ip=66.249.64.5&bot=listbot")
	if resp.StatusCode != 200 || body["result"] != "confirmed" {
		t.Errorf("status %d body %v", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestVerifyBadInput(t *testing.T) {
	srv, _ := newServer(t)
	cases := map[string]string{
		"/v1/verify?ip=foo&bot=listbot":                "invalid_ip",
		"/v1/verify?bot=listbot":                       "invalid_ip",
		"/v1/verify?ip=66.249.64.5&bot=Google%20Bot":   "invalid_bot",
		"/v1/verify?ip=66.249.64.5":                    "invalid_bot",
		"/v1/verify?ip=66.249.64.5%25eth0&bot=listbot": "invalid_ip",
	}
	for path, code := range cases {
		resp, body := get(t, srv, path)
		if resp.StatusCode != 400 || errorCode(body) != code {
			t.Errorf("%s: status %d code %q, want 400 %q", path, resp.StatusCode, errorCode(body), code)
		}
	}
}

func TestVerifyUnknownBot(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := get(t, srv, "/v1/verify?ip=66.249.64.5&bot=ghost")
	if resp.StatusCode != 404 || errorCode(body) != "unknown_bot" {
		t.Errorf("status %d body %v", resp.StatusCode, body)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	srv, _ := newServer(t)
	resp, err := http.Post(srv.URL+"/v1/verify?ip=66.249.64.5&bot=listbot", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status %d, want 405", resp.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	srv, _ := newServer(t)
	for _, path := range []string{"/v1/verify?ip=66.249.64.5&bot=listbot", "/v1/bots", "/v1/dataset", "/healthz", "/nope"} {
		resp, _ := get(t, srv, path)
		h := resp.Header
		if h.Get("X-Content-Type-Options") != "nosniff" ||
			h.Get("Content-Security-Policy") != "default-src 'none'" ||
			h.Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s: headers %v", path, h)
		}
		wantCache := "public, max-age=300"
		if path == "/healthz" || path == "/nope" {
			wantCache = "no-store"
		}
		if h.Get("Cache-Control") != wantCache {
			t.Errorf("%s: Cache-Control = %q, want %q", path, h.Get("Cache-Control"), wantCache)
		}
	}
}

func TestLogsNoIP(t *testing.T) {
	srv, logs := newServer(t)
	get(t, srv, "/v1/verify?ip=66.249.64.5&bot=listbot")
	if !strings.Contains(logs.String(), "/v1/verify") {
		t.Errorf("request not logged: %q", logs.String())
	}
	if strings.Contains(logs.String(), "66.249.64.5") || strings.Contains(logs.String(), "127.0.0.1") {
		t.Errorf("log contains an IP: %q", logs.String())
	}
}

func TestBotsList(t *testing.T) {
	srv, _ := newServer(t)
	resp, err := http.Get(srv.URL + "/v1/bots")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var bots []struct {
		ID        string   `json:"id"`
		Checkable bool     `json:"checkable"`
		Methods   []string `json:"methods"`
	}
	json.NewDecoder(resp.Body).Decode(&bots)
	if len(bots) != 2 || bots[0].ID != "listbot" || !bots[0].Checkable || len(bots[0].Methods) != 1 ||
		bots[1].Checkable || bots[1].Methods == nil {
		t.Errorf("bots = %+v", bots)
	}
}

func TestDatasetShape(t *testing.T) {
	srv, _ := newServer(t)
	resp, err := http.Get(srv.URL + "/v1/dataset")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), `"66.249.64.0/27"`) || !strings.Contains(buf.String(), `"generated_at"`) {
		t.Errorf("dataset = %s", buf.String())
	}
}

func TestHealthz(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := get(t, srv, "/healthz")
	if resp.StatusCode != 200 || body["status"] != "ok" || body["sources_loaded"] != 1.0 || body["sources_total"] != 1.0 {
		t.Errorf("status %d body %v", resp.StatusCode, body)
	}
}

func TestURLsNotHTMLEscaped(t *testing.T) {
	cat := catalog.New([]catalog.Bot{{ID: "ampbot", Name: "AmpBot", NotCheckable: "x", Docs: "https://ops.example/?a=1&b=2"}})
	srv := httptest.NewServer(NewHandler(verify.New(cat, store.New(), noRDNS{}, time.Now), cat, store.New(), slog.New(slog.DiscardHandler)))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/verify?ip=192.0.2.1&bot=ampbot")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	if !strings.Contains(buf.String(), "a=1&b=2") {
		t.Errorf("body = %s", buf.String())
	}
}

type blockingRDNS struct{}

func (blockingRDNS) Check(ctx context.Context, _ netip.Addr, _ []string) (rdns.Outcome, string, error) {
	<-ctx.Done()
	return rdns.NoMatch, "", rdns.ErrLookup
}

func TestVerifyHasDeadline(t *testing.T) {
	old := verifyTimeout
	verifyTimeout = 100 * time.Millisecond
	defer func() { verifyTimeout = old }()
	cat := catalog.New([]catalog.Bot{{ID: "dnsbot", Name: "DNSBot", RDNSSuffixes: []string{"ops.example"}}})
	srv := httptest.NewServer(NewHandler(verify.New(cat, store.New(), blockingRDNS{}, time.Now), cat, store.New(), slog.New(slog.DiscardHandler)))
	defer srv.Close()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(srv.URL + "/v1/verify?ip=192.0.2.1&bot=dnsbot")
	if err != nil {
		t.Fatalf("request did not finish: %v", err)
	}
	defer resp.Body.Close()
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["result"] != "not_checkable" || body["reason"] != "dns lookup failed" {
		t.Errorf("body = %v", body)
	}
}

func readyz(t *testing.T, st *store.Store, cat *catalog.Catalog) (int, map[string]any) {
	t.Helper()
	srv := httptest.NewServer(NewHandler(verify.New(cat, st, noRDNS{}, time.Now), cat, st, slog.New(slog.DiscardHandler)))
	defer srv.Close()
	resp, body := get(t, srv, "/readyz")
	return resp.StatusCode, body
}

func TestReadyz(t *testing.T) {
	cat := catalog.New([]catalog.Bot{{ID: "listbot", Name: "ListBot",
		IPSources: []catalog.IPSource{{URL: listURL, Format: "google-prefixes"}}}})
	empty := catalog.New(nil)

	st := store.New()
	if code, body := readyz(t, st, cat); code != http.StatusServiceUnavailable || body["status"] != "starting" {
		t.Errorf("before first refresh: %d %v, want 503 starting", code, body)
	}
	store.Refresh(context.Background(), empty, nil, st, time.Now) // completes a cycle, loads nothing
	if code, body := readyz(t, st, cat); code != http.StatusServiceUnavailable || body["status"] != "no_sources_loaded" {
		t.Errorf("refreshed, nothing loaded: %d %v, want 503 no_sources_loaded", code, body)
	}
	st.Set(listURL, store.Snapshot{Prefixes: []netip.Prefix{netip.MustParsePrefix("66.249.64.0/27")}, FetchedAt: time.Now()})
	if code, body := readyz(t, st, cat); code != http.StatusOK || body["status"] != "ready" {
		t.Errorf("refreshed and loaded: %d %v, want 200 ready", code, body)
	}
}

func TestDatasetRebuiltOnlyWhenStoreChanges(t *testing.T) {
	cat := catalog.New([]catalog.Bot{{ID: "listbot", Name: "ListBot",
		IPSources: []catalog.IPSource{{URL: listURL, Format: "google-prefixes"}}}})
	st := store.New()
	st.Set(listURL, store.Snapshot{Prefixes: []netip.Prefix{netip.MustParsePrefix("66.249.64.0/27")}, FetchedAt: time.Now()})
	srv := httptest.NewServer(NewHandler(verify.New(cat, st, noRDNS{}, time.Now), cat, st, slog.New(slog.DiscardHandler)))
	defer srv.Close()
	read := func() string {
		resp, err := http.Get(srv.URL + "/v1/dataset")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return buf.String()
	}
	first := read()
	time.Sleep(5 * time.Millisecond)
	if second := read(); second != first {
		t.Error("dataset was rebuilt although the store did not change")
	}
	st.Set(listURL, store.Snapshot{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, FetchedAt: time.Now()})
	if third := read(); !strings.Contains(third, `"192.0.2.0/24"`) {
		t.Errorf("dataset not rebuilt after a store change: %s", third)
	}
}
