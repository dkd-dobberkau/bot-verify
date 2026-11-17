package verify

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"bot-verify/internal/catalog"
	"bot-verify/internal/rdns"
	"bot-verify/internal/store"
)

type fakeRDNS struct {
	outcome  rdns.Outcome
	hostname string
	err      error
	calls    int
}

func (f *fakeRDNS) Check(context.Context, netip.Addr, []string) (rdns.Outcome, string, error) {
	f.calls++
	return f.outcome, f.hostname, f.err
}

const (
	listURL = "https://ops.example/list.json"
	docsURL = "https://ops.example/bots"
)

var now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func testCatalog() *catalog.Catalog {
	src := []catalog.IPSource{{URL: listURL, Format: "google-prefixes"}}
	return catalog.New([]catalog.Bot{
		{ID: "listbot", Name: "ListBot", IPSources: src, Docs: docsURL},
		{ID: "bothbot", Name: "BothBot", IPSources: src, RDNSSuffixes: []string{"ops.example"}, Docs: docsURL},
		{ID: "dnsbot", Name: "DNSBot", RDNSSuffixes: []string{"ops.example"}, Docs: docsURL},
		{ID: "nobot", Name: "NoBot", NotCheckable: "Operator publishes nothing", Docs: docsURL},
	})
}

func loadedStore() *store.Store {
	st := store.New()
	st.Set(listURL, store.Snapshot{
		Prefixes:  []netip.Prefix{netip.MustParsePrefix("66.249.64.0/27")},
		FetchedAt: now.Add(-time.Hour),
	})
	return st
}

func verify(t *testing.T, st *store.Store, r *fakeRDNS, ip, bot string) Result {
	t.Helper()
	res, err := New(testCatalog(), st, r, func() time.Time { return now }).Verify(context.Background(), netip.MustParseAddr(ip), bot)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return res
}

func expect(t *testing.T, res Result, result, method, reason string) {
	t.Helper()
	if res.Result != result || res.Method != method || res.Reason != reason {
		t.Errorf("got (%s, %s, %q), want (%s, %s, %q)", res.Result, res.Method, res.Reason, result, method, reason)
	}
}

func TestVerify_UnknownBot(t *testing.T) {
	_, err := New(testCatalog(), loadedStore(), &fakeRDNS{}, func() time.Time { return now }).
		Verify(context.Background(), netip.MustParseAddr("192.0.2.1"), "ghost")
	if !errors.Is(err, ErrUnknownBot) {
		t.Errorf("err = %v, want ErrUnknownBot", err)
	}
}

func TestVerify_NotCheckable(t *testing.T) {
	res := verify(t, loadedStore(), &fakeRDNS{}, "192.0.2.1", "nobot")
	expect(t, res, "not_checkable", "none", "Operator publishes nothing")
	if len(res.Sources) != 1 || res.Sources[0] != docsURL {
		t.Errorf("Sources = %v, want docs URL", res.Sources)
	}
}

func TestVerify_IPListConfirmed(t *testing.T) {
	res := verify(t, loadedStore(), &fakeRDNS{}, "66.249.64.5", "listbot")
	expect(t, res, "confirmed", "ip_list", "")
	if res.DataAgeSeconds == nil || *res.DataAgeSeconds != 3600 {
		t.Errorf("DataAgeSeconds = %v, want 3600", res.DataAgeSeconds)
	}
	if fmt.Sprint(res.Sources) != fmt.Sprint([]string{listURL, docsURL}) {
		t.Errorf("Sources = %v", res.Sources)
	}
}

func TestVerify_RDNSConfirmed(t *testing.T) {
	r := &fakeRDNS{outcome: rdns.Match, hostname: "crawl-1.ops.example"}
	res := verify(t, store.New(), r, "192.0.2.1", "dnsbot")
	expect(t, res, "confirmed", "rdns", "")
	if res.Hostname != "crawl-1.ops.example" {
		t.Errorf("Hostname = %q", res.Hostname)
	}
}

func TestVerify_RDNSLookupFailed(t *testing.T) {
	r := &fakeRDNS{err: rdns.ErrLookup}
	res := verify(t, loadedStore(), r, "192.0.2.1", "bothbot")
	expect(t, res, "not_checkable", "rdns", "dns lookup failed")
}

func TestVerify_SourceNotLoaded(t *testing.T) {
	res := verify(t, store.New(), &fakeRDNS{}, "66.249.64.5", "listbot")
	expect(t, res, "not_checkable", "ip_list", "source data not loaded")
}

func TestVerify_RefutedByIPList(t *testing.T) {
	res := verify(t, loadedStore(), &fakeRDNS{}, "192.0.2.1", "listbot")
	expect(t, res, "refuted", "ip_list", "")
}

func TestVerify_RefutedByRDNS(t *testing.T) {
	res := verify(t, loadedStore(), &fakeRDNS{outcome: rdns.NoMatch}, "192.0.2.1", "bothbot")
	expect(t, res, "refuted", "rdns", "")
}

func TestVerifyUnmapsIPv4(t *testing.T) {
	res := verify(t, loadedStore(), &fakeRDNS{}, "::ffff:66.249.64.5", "listbot")
	expect(t, res, "confirmed", "ip_list", "")
	if res.IP != "66.249.64.5" {
		t.Errorf("IP = %q, want 66.249.64.5", res.IP)
	}
}

func TestVerifyIPListBeforeRDNS(t *testing.T) {
	r := &fakeRDNS{outcome: rdns.Match}
	res := verify(t, loadedStore(), r, "66.249.64.5", "bothbot")
	expect(t, res, "confirmed", "ip_list", "")
	if r.calls != 0 {
		t.Errorf("rdns calls = %d, want 0", r.calls)
	}
}
