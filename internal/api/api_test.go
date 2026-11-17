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

	"bot-verify/internal/catalog"
	"bot-verify/internal/rdns"
	"bot-verify/internal/store"
	"bot-verify/internal/verify"
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
