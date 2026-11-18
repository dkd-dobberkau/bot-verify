package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const zone = "verify.example"

// productionFetchClient is captured before any test replaces newFetchClient.
var productionFetchClient = newFetchClient

func writeCatalog(t *testing.T, sourceURL string) string {
	t.Helper()
	bots := filepath.Join(t.TempDir(), "bots.yaml")
	yaml := "bots:\n  - id: listbot\n    name: ListBot\n    ip_sources:\n      - url: " + sourceURL + "\n        format: google-prefixes\n"
	if err := os.WriteFile(bots, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return bots
}

func zoneArgs(bots string) []string {
	return []string{"-listen", "127.0.0.1:0", "-bots", bots, "-zone", zone,
		"-ns", "ns1." + zone + "=127.0.0.1", "-hostmaster", "hostmaster." + zone}
}

// startRun runs run with args and returns the address it listens on and a
// stop function that cancels it and checks it returned nil within 5 s.
func startRun(t *testing.T, args []string) (addr string, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	out, stdout := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := run(ctx, args, stdout)
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
			t.Fatal("run did not return within 5s after cancel")
		}
	}
}

func query(network, addr, qname string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	resp, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(m, addr)
	return resp, err
}

func TestRunAnswersFromFetchedList(t *testing.T) {
	src := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"192.0.2.0/24"}]}`))
	}))
	defer src.Close()
	newFetchClient = func() *http.Client { return src.Client() }

	addr, stop := startRun(t, zoneArgs(writeCatalog(t, src.URL)))
	defer stop()
	confirmed := "7.2.0.192.listbot." + zone
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if resp, err := query("udp", addr, confirmed); err == nil && len(resp.Answer) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no A answer within 5s")
		}
	}
	if resp, err := query("tcp", addr, confirmed); err != nil || len(resp.Answer) != 1 {
		t.Errorf("over TCP on the same address: %v, %v", resp, err)
	}
	if resp, err := query("udp", addr, "8.51.100.198.listbot."+zone); err != nil || resp.Rcode != dns.RcodeNameError {
		t.Errorf("address outside the list: %v, %v; want NXDOMAIN", resp, err)
	}
}

func TestRunRejectsNSLabelClash(t *testing.T) {
	args := zoneArgs(writeCatalog(t, "https://ops.example/list.json"))
	args = append(args, "-ns", "listbot."+zone+"=192.0.2.53")
	err := run(context.Background(), args, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "listbot") {
		t.Errorf("run = %v, want an error naming the listbot clash", err)
	}
}

func TestRunRejectsUnusableNS(t *testing.T) {
	bots := writeCatalog(t, "https://ops.example/list.json")
	cases := map[string]string{
		"ns is the zone apex":        "Verify.Example.=192.0.2.53",
		"in-zone ns without address": "ns2." + zone,
		"ns below an invalid name":   "ns1.a-b.c." + zone + "=192.0.2.53",
	}
	for name, ns := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := run(ctx, append(zoneArgs(bots), "-ns", ns), io.Discard); err == nil {
			t.Errorf("%s: run returned nil", name)
		}
	}
	// A name server outside the zone needs no address here.
	addr, stop := startRun(t, append(zoneArgs(bots), "-ns", "ns.other.example"))
	defer stop()
	if addr == "" {
		t.Error("no listen address with an out-of-zone NS")
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	bots := writeCatalog(t, "https://ops.example/list.json")
	cases := map[string][]string{
		"no zone":        {"-bots", bots, "-ns", "ns1." + zone, "-hostmaster", "hostmaster." + zone},
		"invalid zone":   {"-bots", bots, "-zone", "bad zone", "-ns", "ns1." + zone, "-hostmaster", "hostmaster." + zone},
		"no ns":          {"-bots", bots, "-zone", zone, "-hostmaster", "hostmaster." + zone},
		"bad glue":       {"-bots", bots, "-zone", zone, "-ns", "ns1." + zone + "=nope", "-hostmaster", "hostmaster." + zone},
		"no hostmaster":  {"-bots", bots, "-zone", zone, "-ns", "ns1." + zone},
		"tcp max conns":  {"-bots", bots, "-zone", zone, "-ns", "ns1." + zone + "=192.0.2.53", "-hostmaster", "hostmaster." + zone, "-tcp-max-conns", "0"},
		"tcp per source": {"-bots", bots, "-zone", zone, "-ns", "ns1." + zone + "=192.0.2.53", "-hostmaster", "hostmaster." + zone, "-tcp-max-per-source", "0"},
	}
	for name, args := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := run(ctx, append([]string{"-listen", "127.0.0.1:0"}, args...), io.Discard); err == nil {
			t.Errorf("%s: run returned nil", name)
		}
	}
}

func TestProbe(t *testing.T) {
	newFetchClient = productionFetchClient
	addr, stop := startRun(t, zoneArgs(writeCatalog(t, "https://ops.example/list.json")))
	if err := run(context.Background(), []string{"-probe", "-listen", addr, "-zone", zone}, io.Discard); err != nil {
		t.Errorf("probe of a running server: %v", err)
	}
	if err := run(context.Background(), []string{"-probe", "-listen", addr}, io.Discard); err != nil {
		t.Errorf("probe without -zone: %v", err)
	}
	stop()
	if err := run(context.Background(), []string{"-probe", "-listen", addr, "-zone", zone}, io.Discard); err == nil {
		t.Error("probe of a stopped server returned nil")
	}
}

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
	if resp, err := client.Get(source.URL); err == nil {
		resp.Body.Close()
		t.Error("production fetch client followed an https to http redirect")
	}
	if plainHits != 0 {
		t.Errorf("plain-http origin was requested %d times, want 0", plainHits)
	}
}

func TestListenBothUsesOnePort(t *testing.T) {
	pc, ln, err := listenBoth("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	defer ln.Close()
	_, udpPort, _ := net.SplitHostPort(pc.LocalAddr().String())
	_, tcpPort, _ := net.SplitHostPort(ln.Addr().String())
	if udpPort != tcpPort {
		t.Errorf("UDP port %s, TCP port %s; want the same", udpPort, tcpPort)
	}
}
