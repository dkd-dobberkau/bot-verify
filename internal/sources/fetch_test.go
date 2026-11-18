package sources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchSendsConditionalHeaders(t *testing.T) {
	var gotETag, gotSince, gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotETag, gotSince, gotUA = r.Header.Get("If-None-Match"), r.Header.Get("If-Modified-Since"), r.UserAgent()
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()
	prev := FetchState{ETag: `"a"`, LastModified: "Tue, 17 Nov 2026 10:00:00 GMT"}
	res, err := Fetch(context.Background(), srv.Client(), srv.URL, prev)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.NotModified {
		t.Error("NotModified = false, want true")
	}
	if gotETag != `"a"` || gotSince != prev.LastModified {
		t.Errorf("headers: If-None-Match=%q If-Modified-Since=%q", gotETag, gotSince)
	}
	if !strings.HasPrefix(gotUA, "bot-verify/") {
		t.Errorf("User-Agent = %q", gotUA)
	}
	if res.State != prev {
		t.Errorf("State = %+v, want previous state kept on 304", res.State)
	}
}

func TestFetchReturnsBodyAndState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"b"`)
		w.Header().Set("Last-Modified", "Tue, 17 Nov 2026 11:00:00 GMT")
		w.Write([]byte("192.0.2.1\n"))
	}))
	defer srv.Close()
	res, err := Fetch(context.Background(), srv.Client(), srv.URL, FetchState{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(res.Body) != "192.0.2.1\n" || res.State.ETag != `"b"` || res.State.LastModified == "" || res.NotModified {
		t.Errorf("got %+v", res)
	}
}

func TestFetchRejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, FetchState{}); err == nil {
		t.Error("no error for status 500")
	}
}

func TestFetchRejectsOversize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, MaxBodyBytes+1))
	}))
	defer srv.Close()
	if _, err := Fetch(context.Background(), srv.Client(), srv.URL, FetchState{}); err == nil {
		t.Error("no error for oversize body")
	}
}

// downgradeServers returns an https source that redirects to a plain-http
// origin, and a counter of requests that reached the plain origin.
func downgradeServers(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"}]}`))
	}))
	t.Cleanup(plain.Close)
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/list.json", http.StatusFound)
	}))
	t.Cleanup(source.Close)
	return source, &plainHits
}

func TestFetchRejectsDowngradeWithoutRedirectPolicy(t *testing.T) {
	source, _ := downgradeServers(t)
	if _, err := Fetch(context.Background(), source.Client(), source.URL, FetchState{}); err == nil {
		t.Error("Fetch accepted a body served over http after an https source redirected")
	}
}

func TestRejectDowngradeStopsTheRedirect(t *testing.T) {
	source, plainHits := downgradeServers(t)
	client := source.Client()
	client.CheckRedirect = RejectDowngrade
	if _, err := Fetch(context.Background(), client, source.URL, FetchState{}); err == nil {
		t.Error("Fetch accepted an https to http redirect")
	}
	if plainHits.Load() != 0 {
		t.Errorf("plain-http origin was requested %d times, want 0", plainHits.Load())
	}
}

func TestRejectDowngradeAllowsHTTPSRedirect(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("192.0.2.1\n"))
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/list.txt", http.StatusMovedPermanently)
	}))
	defer source.Close()
	client := target.Client() // both test servers share the httptest CA
	client.CheckRedirect = RejectDowngrade
	res, err := Fetch(context.Background(), client, source.URL, FetchState{})
	if err != nil || string(res.Body) != "192.0.2.1\n" {
		t.Errorf("https redirect: body %q err %v", res.Body, err)
	}
}

func TestIsPublicAddr(t *testing.T) {
	cases := map[string]bool{
		"66.249.66.1":          true,
		"2001:4860:4801:10::1": true,
		"127.0.0.1":            false,
		"::1":                  false,
		"10.1.2.3":             false,
		"172.16.0.1":           false,
		"192.168.1.1":          false,
		"169.254.169.254":      false, // cloud metadata endpoint
		"fe80::1":              false,
		"fc00::1":              false,
		"100.64.0.1":           false, // carrier-grade NAT
		"0.0.0.0":              false,
		"::ffff:127.0.0.1":     false,
		"224.0.0.1":            false,
		// Special-purpose ranges that are global unicast to netip but not
		// the public internet (RFC 6890 registry).
		"198.18.0.1":         false, // benchmarking
		"192.0.0.1":          false, // IETF protocol assignments
		"240.0.0.1":          false, // reserved
		"0.1.2.3":            false, // "this network"
		"192.0.2.1":          false, // TEST-NET-1
		"198.51.100.1":       false, // TEST-NET-2
		"203.0.113.1":        false, // TEST-NET-3
		"2001:db8::1":        false, // IPv6 documentation
		"::a00:1":            false, // IPv4-compatible (deprecated), 10.0.0.1
		"64:ff9b:1::1":       false, // local-use NAT64
		"64:ff9b::a00:1":     false, // NAT64 to 10.0.0.1
		"64:ff9b::4242:4201": true,  // NAT64 to 66.66.66.1
		"2002:a00:1::1":      false, // 6to4 relay for 10.0.0.1
		"2002:4242:4201::1":  true,  // 6to4 relay for 66.66.66.1
	}
	for addr, want := range cases {
		if got := isPublicAddr(netip.MustParseAddr(addr)); got != want {
			t.Errorf("isPublicAddr(%s) = %v, want %v", addr, got, want)
		}
	}
}

func TestNewClientRefusesNonPublicDestinations(t *testing.T) {
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer internal.Close()
	client := NewClient(5 * time.Second)
	if _, err := Fetch(context.Background(), client, internal.URL, FetchState{}); err == nil {
		t.Error("fetch client connected to a loopback address")
	}
	if hits.Load() != 0 {
		t.Errorf("internal server was requested %d times, want 0", hits.Load())
	}
	if client.CheckRedirect == nil {
		t.Error("NewClient must refuse https to http redirects")
	}
}
