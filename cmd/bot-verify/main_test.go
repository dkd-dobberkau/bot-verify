package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
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
