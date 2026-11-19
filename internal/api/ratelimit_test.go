package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/ratelimit"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
	"github.com/dkd-dobberkau/bot-verify/internal/verify"
)

var proxyNet = []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}

func TestClientAddr(t *testing.T) {
	cases := []struct {
		name, peer string
		forwarded  []string
		want       string
	}{
		{"no proxy configured header is ignored", "198.51.100.20:4000", []string{"203.0.113.77"}, "198.51.100.20"},
		{"normal visitor behind the proxy", "100.125.119.41:4000", []string{"198.51.100.9"}, "198.51.100.9"},
		{"a client-supplied entry is ignored, the proxy's appended one wins", "100.125.119.41:4000", []string{"203.0.113.77, 198.51.100.9"}, "198.51.100.9"},
		{"the last of several headers counts", "100.125.119.41:4000", []string{"203.0.113.77", "198.51.100.9"}, "198.51.100.9"},
		{"internal proxy hops are skipped", "100.125.119.41:4000", []string{"203.0.113.77, 198.51.100.9, 100.125.0.3"}, "198.51.100.9"},
		{"a peer outside the proxy network cannot set its address", "198.51.100.20:4000", []string{"203.0.113.77"}, "198.51.100.20"},
		{"the proxy without a header counts as itself", "100.125.119.41:4000", nil, "100.125.119.41"},
		{"a malformed entry stops the walk at the last trusted hop", "100.125.119.41:4000", []string{"198.51.100.9, junk"}, "100.125.119.41"},
		{"an entry with a port is malformed", "100.125.119.41:4000", []string{"198.51.100.9:443"}, "100.125.119.41"},
		{"IPv4-mapped peers count as IPv4", "[::ffff:100.125.119.41]:4000", []string{"198.51.100.9"}, "198.51.100.9"},
		{"IPv6 client", "100.125.119.41:4000", []string{"2001:db8::1"}, "2001:db8::1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/v1/bots", nil)
			r.RemoteAddr = c.peer
			for _, v := range c.forwarded {
				r.Header.Add("X-Forwarded-For", v)
			}
			trusted := proxyNet
			if c.name == "no proxy configured header is ignored" {
				trusted = nil
			}
			got, ok := clientAddr(r, trusted)
			if !ok || got != netip.MustParseAddr(c.want) {
				t.Errorf("clientAddr = %v, %v; want %s", got, ok, c.want)
			}
		})
	}
}

func limitedServer(t *testing.T, limit ClientLimit) *httptest.Server {
	t.Helper()
	cat := catalog.New([]catalog.Bot{{ID: "nobot", Name: "NoBot", NotCheckable: "nothing published"}})
	st := store.New()
	srv := httptest.NewServer(NewHandler(verify.New(cat, st, noRDNS{}, time.Now), cat, st, slog.New(slog.DiscardHandler), limit))
	t.Cleanup(srv.Close)
	return srv
}

func TestRateLimitedRequestsGet429(t *testing.T) {
	srv := limitedServer(t, ClientLimit{Limiter: ratelimit.New(1, 2), Now: time.Now})
	for i := range 2 {
		if resp, _ := get(t, srv, "/v1/bots"); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d within the burst: status %d", i+1, resp.StatusCode)
		}
	}
	resp, body := get(t, srv, "/v1/verify?ip=66.249.64.5&bot=nobot")
	if resp.StatusCode != http.StatusTooManyRequests || errorCode(body) != "rate_limited" {
		t.Fatalf("over the burst: status %d, code %q; want 429 rate_limited", resp.StatusCode, errorCode(body))
	}
	if resp.Header.Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q, want 1", resp.Header.Get("Retry-After"))
	}
	if resp.Header.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Error("a 429 lacks the security headers")
	}
}

func TestHealthEndpointsAreNotLimited(t *testing.T) {
	srv := limitedServer(t, ClientLimit{Limiter: ratelimit.New(1, 1), Now: time.Now})
	get(t, srv, "/v1/bots")
	for _, path := range []string{"/healthz", "/readyz"} {
		if resp, _ := get(t, srv, path); resp.StatusCode == http.StatusTooManyRequests {
			t.Errorf("%s was rate limited; the container health check uses it", path)
		}
	}
}

func TestNoLimiterMeansNoLimit(t *testing.T) {
	srv := limitedServer(t, ClientLimit{})
	for range 50 {
		if resp, _ := get(t, srv, "/v1/bots"); resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d without a limiter", resp.StatusCode)
		}
	}
}
