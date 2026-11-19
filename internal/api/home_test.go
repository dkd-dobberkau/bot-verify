package api

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"testing"
)

func getText(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func TestHomePage(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := getText(t, srv.URL+"/")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("status %d, Content-Type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for _, want := range []string{"/v1/verify?ip=", "goodbot-badbot.com/impressum", "goodbot-badbot.com/datenschutz", "github.com/dkd-dobberkau/bot-verify"} {
		if !strings.Contains(body, want) {
			t.Errorf("home page lacks %q", want)
		}
	}
}

// The page's only style is its inline block, allowed by hash; everything else
// stays at default-src 'none'.
func TestHomePageCSPAllowsExactlyItsStyle(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := getText(t, srv.URL+"/")
	start := strings.Index(body, "<style>") + len("<style>")
	end := strings.Index(body, "</style>")
	sum := sha256.Sum256([]byte(body[start:end]))
	want := "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	if got := resp.Header.Get("Content-Security-Policy"); got != want {
		t.Errorf("CSP = %q, want %q", got, want)
	}
	if strings.Contains(body, "<script") || strings.Count(body, "<style") != 1 {
		t.Error("the page must have no script and exactly one style block")
	}
}

func TestOnlyRootServesTheHomePage(t *testing.T) {
	srv, _ := newServer(t)
	for _, path := range []string{"/index.html", "/nope", "/v1/"} {
		if resp, _ := getText(t, srv.URL+path); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, resp.StatusCode)
		}
	}
	if resp, _ := getText(t, srv.URL+"/healthz"); resp.Header.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Error("the home page's CSP leaked to other paths")
	}
}

func TestRobotsTxtKeepsCrawlersOffTheAPI(t *testing.T) {
	srv, _ := newServer(t)
	resp, body := getText(t, srv.URL+"/robots.txt")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("status %d, Content-Type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if body != "User-agent: *\nDisallow: /v1/\n" {
		t.Errorf("robots.txt = %q", body)
	}
}
