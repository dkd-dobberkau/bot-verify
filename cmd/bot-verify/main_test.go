package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunServesHealthz(t *testing.T) {
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`))
	}))
	defer src.Close()
	newFetchClient = func() *http.Client { return src.Client() }

	bots := filepath.Join(t.TempDir(), "bots.yaml")
	yaml := "bots:\n  - id: testbot\n    name: TestBot\n    ip_sources:\n      - url: " + src.URL + "\n        format: google-prefixes\n"
	if err := os.WriteFile(bots, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	out, stdout := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"-listen", "127.0.0.1:0", "-bots", bots}, stdout) }()

	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("reading listen line: %v", err)
	}
	go io.Copy(io.Discard, out)
	addr := strings.TrimSpace(strings.TrimPrefix(line, "listening on "))

	deadline := time.Now().Add(5 * time.Second)
	for {
		var health struct {
			SourcesLoaded int `json:"sources_loaded"`
		}
		if resp, err := http.Get("http://" + addr + "/healthz"); err == nil {
			json.NewDecoder(resp.Body).Decode(&health)
			resp.Body.Close()
		}
		if health.SourcesLoaded == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("source not loaded within 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

func TestProbe(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
		}
	}))
	defer healthy.Close()
	addr := strings.TrimPrefix(healthy.URL, "http://")
	if err := run(context.Background(), []string{"-probe", "-listen", addr}, io.Discard); err != nil {
		t.Errorf("probe of healthy server: %v", err)
	}
	healthy.Close()
	if err := run(context.Background(), []string{"-probe", "-listen", addr}, io.Discard); err == nil {
		t.Error("probe of stopped server returned nil")
	}
}

// productionFetchClient is captured before any test replaces newFetchClient.
var productionFetchClient = newFetchClient

func TestFetchClientRefusesHTTPSDowngrade(t *testing.T) {
	var plainHits int
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { plainHits++ }))
	defer plain.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL, http.StatusFound)
	}))
	defer source.Close()
	client := productionFetchClient()
	client.Transport = source.Client().Transport // trust the test CA, keep the production policy
	resp, err := client.Get(source.URL)
	if err == nil {
		resp.Body.Close()
		t.Error("production fetch client followed an https to http redirect")
	}
	if plainHits != 0 {
		t.Errorf("plain-http origin was requested %d times, want 0", plainHits)
	}
}

func TestServerRejectsOversizedHeaders(t *testing.T) {
	server := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(listener)
	defer server.Close()
	req, _ := http.NewRequest("GET", "http://"+listener.Addr().String()+"/healthz", nil)
	req.Header.Set("X-Filler", strings.Repeat("a", 32<<10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("status %d for a 32 KiB header, want 431", resp.StatusCode)
	}
}
