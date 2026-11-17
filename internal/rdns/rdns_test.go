package rdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeResolver struct {
	mu       sync.Mutex
	ptr      map[string][]string
	ptrErr   error
	forward  map[string][]string
	ptrCalls int
	fwdCalls int
}

func (f *fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ptrCalls++
	if f.ptrErr != nil {
		return nil, f.ptrErr
	}
	names, ok := f.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return names, nil
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fwdCalls++
	var out []net.IPAddr
	for _, ip := range f.forward[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(ip)})
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

var (
	googleIP = netip.MustParseAddr("66.249.66.1")
	google   = []string{"googlebot.com", "google.com"}
	t0       = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
)

func newChecker(r Resolver, now *time.Time) *Checker {
	return NewChecker(r, 15*time.Minute, 4, func() time.Time { return *now })
}

func check(t *testing.T, r *fakeResolver, ip netip.Addr, suffixes []string) (Outcome, string) {
	t.Helper()
	now := t0
	outcome, host, err := newChecker(r, &now).Check(context.Background(), ip, suffixes)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return outcome, host
}

func TestMatchForwardConfirmed(t *testing.T) {
	r := &fakeResolver{
		ptr:     map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		forward: map[string][]string{"crawl-66-249-66-1.googlebot.com.": {"66.249.66.1"}},
	}
	outcome, host := check(t, r, googleIP, google)
	if outcome != Match || host != "crawl-66-249-66-1.googlebot.com" {
		t.Errorf("got %v %q", outcome, host)
	}
}

func TestForwardMismatch(t *testing.T) {
	r := &fakeResolver{
		ptr:     map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		forward: map[string][]string{"crawl-66-249-66-1.googlebot.com.": {"203.0.113.9"}},
	}
	if outcome, _ := check(t, r, googleIP, google); outcome != NoMatch {
		t.Errorf("got %v, want NoMatch", outcome)
	}
}

func TestSuffixBoundary(t *testing.T) {
	r := &fakeResolver{ptr: map[string][]string{"66.249.66.1": {"evilgooglebot.com."}},
		forward: map[string][]string{"evilgooglebot.com.": {"66.249.66.1"}}}
	if outcome, _ := check(t, r, googleIP, []string{"googlebot.com"}); outcome != NoMatch {
		t.Errorf("evilgooglebot.com: got %v, want NoMatch", outcome)
	}
	if r.fwdCalls != 0 {
		t.Errorf("forward lookups = %d, want 0", r.fwdCalls)
	}
	for _, name := range []string{"googlebot.com.", "GoogleBot.COM."} {
		r := &fakeResolver{ptr: map[string][]string{"66.249.66.1": {name}},
			forward: map[string][]string{name: {"66.249.66.1"}}}
		if outcome, _ := check(t, r, googleIP, []string{"googlebot.com"}); outcome != Match {
			t.Errorf("%s: got %v, want Match", name, outcome)
		}
	}
}

func TestNXDOMAINIsNoMatch(t *testing.T) {
	if outcome, _ := check(t, &fakeResolver{}, googleIP, google); outcome != NoMatch {
		t.Errorf("got %v, want NoMatch", outcome)
	}
}

func TestTransientIsErrorAndNotCached(t *testing.T) {
	r := &fakeResolver{ptrErr: &net.DNSError{Err: "i/o timeout", IsTimeout: true}}
	now := t0
	c := newChecker(r, &now)
	for i := 0; i < 2; i++ {
		_, _, err := c.Check(context.Background(), googleIP, google)
		if !errors.Is(err, ErrLookup) {
			t.Fatalf("call %d: err = %v, want ErrLookup", i, err)
		}
	}
	if r.ptrCalls != 2 {
		t.Errorf("PTR lookups = %d, want 2 (errors must not be cached)", r.ptrCalls)
	}
}

func TestResultCached(t *testing.T) {
	r := &fakeResolver{
		ptr:     map[string][]string{"66.249.66.1": {"crawl.googlebot.com."}},
		forward: map[string][]string{"crawl.googlebot.com.": {"66.249.66.1"}},
	}
	now := t0
	c := newChecker(r, &now)
	c.Check(context.Background(), googleIP, google)
	c.Check(context.Background(), googleIP, google)
	if r.ptrCalls != 1 {
		t.Errorf("PTR lookups within TTL = %d, want 1", r.ptrCalls)
	}
	now = t0.Add(16 * time.Minute)
	outcome, host, _ := c.Check(context.Background(), googleIP, google)
	if r.ptrCalls != 2 {
		t.Errorf("PTR lookups after TTL = %d, want 2", r.ptrCalls)
	}
	if outcome != Match || host != "crawl.googlebot.com" {
		t.Errorf("got %v %q", outcome, host)
	}
}

func TestMultiplePTRs(t *testing.T) {
	r := &fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"other.example.", "fake.googlebot.com.", "crawl.googlebot.com."}},
		forward: map[string][]string{
			"fake.googlebot.com.":  {"203.0.113.9"},
			"crawl.googlebot.com.": {"66.249.66.1"},
		},
	}
	outcome, host := check(t, r, googleIP, google)
	if outcome != Match || host != "crawl.googlebot.com" {
		t.Errorf("got %v %q", outcome, host)
	}
}

func TestIPv6ForwardConfirmed(t *testing.T) {
	ip := netip.MustParseAddr("2001:4860:4801:10::1")
	r := &fakeResolver{
		ptr:     map[string][]string{ip.String(): {"crawl.googlebot.com."}},
		forward: map[string][]string{"crawl.googlebot.com.": {"2001:4860:4801:10::1"}},
	}
	if outcome, _ := check(t, r, ip, google); outcome != Match {
		t.Errorf("got %v, want Match", outcome)
	}
}
