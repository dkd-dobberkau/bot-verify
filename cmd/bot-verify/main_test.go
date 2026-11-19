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
	"sync/atomic"
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

// startRun runs run with args and returns the HTTP address it listens on and
// a stop function that cancels it and checks it returned nil.
func startRun(t *testing.T, args ...string) (addr string, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out, stdout := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := run(ctx, append([]string{"-listen", "127.0.0.1:0"}, args...), stdout)
		stdout.Close() // a run that fails before listening must not leave the reader blocked
		done <- err
	}()
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		cancel()
		t.Fatalf("reading listen line: %v (run: %v)", err, <-done)
	}
	go io.Copy(io.Discard, out)
	return strings.TrimSpace(strings.TrimPrefix(line, "listening on ")), func() {
		t.Helper()
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
}

func sourcesLoaded(addr string) (int, bool) {
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var health struct {
		SourcesLoaded int `json:"sources_loaded"`
	}
	json.NewDecoder(resp.Body).Decode(&health)
	return health.SourcesLoaded, true
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !ok(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%s not reached within 5s", what)
		}
	}
}

func TestRunWritesAndLoadsSnapshot(t *testing.T) {
	var failing atomic.Bool
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`))
	}))
	defer src.Close()
	newFetchClient = func() *http.Client { return src.Client() }

	dir := t.TempDir()
	bots := filepath.Join(dir, "bots.yaml")
	yaml := "bots:\n  - id: testbot\n    name: TestBot\n    ip_sources:\n      - url: " + src.URL + "\n        format: google-prefixes\n"
	if err := os.WriteFile(bots, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(dir, "s.jsonl")

	addr, stop := startRun(t, "-bots", bots, "-snapshot", snap)
	waitFor(t, "sources_loaded == 1", func() bool { n, _ := sourcesLoaded(addr); return n == 1 })
	waitFor(t, "snapshot written", func() bool { _, err := os.Stat(snap); return err == nil })
	stop()

	failing.Store(true)
	addr, stop = startRun(t, "-bots", bots, "-snapshot", snap)
	defer stop()
	var loaded int
	waitFor(t, "first /healthz", func() bool { n, ok := sourcesLoaded(addr); loaded = n; return ok })
	if loaded != 1 {
		t.Errorf("first /healthz after restart: sources_loaded = %d, want 1 from the snapshot", loaded)
	}
	resp, err := http.Get("http://" + addr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/readyz after restart = %d, want 200", resp.StatusCode)
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

func writeNoSourceBots(t *testing.T) string {
	t.Helper()
	bots := filepath.Join(t.TempDir(), "bots.yaml")
	yaml := "bots:\n  - id: nobot\n    name: NoBot\n    not_checkable: nothing published\n    docs: https://ops.example/bots\n"
	if err := os.WriteFile(bots, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return bots
}

func TestRunRateLimitsClients(t *testing.T) {
	addr, stop := startRun(t, "-bots", writeNoSourceBots(t), "-rate-limit", "1", "-rate-burst", "1")
	defer stop()
	var codes []int
	for range 2 {
		resp, err := http.Get("http://" + addr + "/v1/bots")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		codes = append(codes, resp.StatusCode)
	}
	if codes[0] != http.StatusOK || codes[1] != http.StatusTooManyRequests {
		t.Errorf("statuses %v, want [200 429]", codes)
	}
}

func TestRunRejectsBadLimitFlags(t *testing.T) {
	bots := writeNoSourceBots(t)
	for _, args := range [][]string{
		{"-rate-limit", "-1"},
		{"-rate-limit", "5", "-rate-burst", "0"},
		{"-trusted-proxy", "100.64.0.0"},
		{"-trusted-proxy", "100.64.0.0/10,junk"},
	} {
		err := run(context.Background(), append([]string{"-listen", "127.0.0.1:0", "-bots", bots}, args...), io.Discard)
		if err == nil {
			t.Errorf("%v: run accepted it", args)
		}
	}
}
