package dnszone

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/dkd-dobberkau/bot-verify/internal/store"
)

type testServer struct {
	udp, tcp string
	handler  *Handler
}

// startServer serves cfg on loopback UDP and TCP until the test ends.
func startServer(t *testing.T, cfg Config) testServer {
	t.Helper()
	h := NewHandler(cfg)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	for _, srv := range []*dns.Server{{PacketConn: pc, Handler: h}, {Listener: ln, Handler: h}} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go srv.ActivateAndServe()
		<-started
		t.Cleanup(func() { srv.Shutdown() })
	}
	return testServer{udp: pc.LocalAddr().String(), tcp: ln.Addr().String(), handler: h}
}

func testConfig() Config {
	return Config{
		Zone:       zone,
		NS:         []NameServer{{Name: "ns1." + zone, Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}, {Name: "ns.other.example"}},
		Hostmaster: "hostmaster." + zone,
		Catalog:    testCatalog(),
		Store:      storeWith(map[string]time.Time{listURL: now.Add(-time.Hour)}),
		Now:        func() time.Time { return now },
		Limiter:    NewLimiter(1000, 1000),
	}
}

func exchange(t *testing.T, network, addr, qname string, qtype uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), qtype)
	resp, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s %s: %v", network, qname, err)
	}
	return resp
}

func expectNegative(t *testing.T, resp *dns.Msg, rcode int) {
	t.Helper()
	if resp.Rcode != rcode || len(resp.Answer) != 0 || !resp.Authoritative {
		t.Fatalf("rcode %s, %d answers, AA %v; want %s, none, AA", dns.RcodeToString[resp.Rcode], len(resp.Answer), resp.Authoritative, dns.RcodeToString[rcode])
	}
	if len(resp.Ns) != 1 {
		t.Fatalf("authority = %v, want the zone SOA", resp.Ns)
	}
	soa, ok := resp.Ns[0].(*dns.SOA)
	if !ok || soa.Hdr.Name != zone+"." || soa.Minttl != 300 {
		t.Errorf("authority = %v, want SOA for %s with minimum 300", resp.Ns[0], zone)
	}
}

func expectConfirmed(t *testing.T, resp *dns.Msg) {
	t.Helper()
	if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || len(resp.Answer) != 1 {
		t.Fatalf("rcode %s AA %v answers %v", dns.RcodeToString[resp.Rcode], resp.Authoritative, resp.Answer)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !ok || !a.A.Equal(net.IPv4(127, 0, 0, 2)) || a.Hdr.Ttl != 300 {
		t.Errorf("answer = %v, want A 127.0.0.2 TTL 300", resp.Answer[0])
	}
}

func TestServe_Confirmed(t *testing.T) {
	srv := startServer(t, testConfig())
	expectConfirmed(t, exchange(t, "udp", srv.udp, "5.64.249.66.listbot."+zone, dns.TypeA))
	if got := srv.handler.Counters().Confirmed.Load(); got != 1 {
		t.Errorf("Confirmed counter = %d, want 1", got)
	}
}

func TestServe_ConfirmedOtherTypeIsNoData(t *testing.T) {
	srv := startServer(t, testConfig())
	expectNegative(t, exchange(t, "udp", srv.udp, "5.64.249.66.listbot."+zone, dns.TypeTXT), dns.RcodeSuccess)
}

func TestServe_NXDomain(t *testing.T) {
	srv := startServer(t, testConfig())
	expectNegative(t, exchange(t, "udp", srv.udp, "1.2.0.192.listbot."+zone, dns.TypeA), dns.RcodeNameError)
}

func TestServe_NoDataForNotLoadedList(t *testing.T) {
	srv := startServer(t, testConfig())
	expectNegative(t, exchange(t, "udp", srv.udp, "1.2.0.192.twobot."+zone, dns.TypeA), dns.RcodeSuccess)
}

func TestServe_Apex(t *testing.T) {
	cfg := testConfig()
	cfg.Store.Set(list2URL, store.Snapshot{Prefixes: listPrefixes, FetchedAt: now})
	srv := startServer(t, cfg)

	resp := exchange(t, "udp", srv.udp, zone, dns.TypeSOA)
	soa, ok := firstAnswer(resp).(*dns.SOA)
	if !ok || !resp.Authoritative || soa.Ns != "ns1."+zone+"." || soa.Mbox != "hostmaster."+zone+"." ||
		soa.Serial != uint32(cfg.Store.Version()) || soa.Refresh != 3600 || soa.Retry != 600 || soa.Expire != 86400 || soa.Minttl != 300 {
		t.Errorf("SOA answer = %v", resp)
	}

	resp = exchange(t, "udp", srv.udp, zone, dns.TypeNS)
	if len(resp.Answer) != 2 || !resp.Authoritative {
		t.Fatalf("NS answer = %v", resp.Answer)
	}
	if ns, ok := resp.Answer[0].(*dns.NS); !ok || ns.Ns != "ns1."+zone+"." {
		t.Errorf("first NS = %v", resp.Answer[0])
	}
	if len(resp.Extra) != 1 {
		t.Errorf("additional = %v, want glue for ns1 only", resp.Extra)
	}
}

func TestServe_SerialWithEmptyStoreIsOne(t *testing.T) {
	cfg := testConfig()
	cfg.Store = store.New()
	srv := startServer(t, cfg)
	if soa, ok := firstAnswer(exchange(t, "udp", srv.udp, zone, dns.TypeSOA)).(*dns.SOA); !ok || soa.Serial != 1 {
		t.Errorf("SOA = %v, want serial 1", soa)
	}
}

func TestServe_Glue(t *testing.T) {
	srv := startServer(t, testConfig())
	resp := exchange(t, "udp", srv.udp, "NS1."+zone, dns.TypeA)
	a, ok := firstAnswer(resp).(*dns.A)
	if !ok || !a.A.Equal(net.IPv4(192, 0, 2, 53)) || !resp.Authoritative {
		t.Errorf("glue answer = %v", resp)
	}
	expectNegative(t, exchange(t, "udp", srv.udp, "ns1."+zone, dns.TypeAAAA), dns.RcodeSuccess)
}

func TestServe_Refused(t *testing.T) {
	srv := startServer(t, testConfig())
	if resp := exchange(t, "udp", srv.udp, "example.com", dns.TypeA); resp.Rcode != dns.RcodeRefused || len(resp.Answer) != 0 {
		t.Errorf("out of zone: %v", resp)
	}
	m := new(dns.Msg)
	m.SetQuestion("5.64.249.66.listbot."+zone+".", dns.TypeA)
	m.Question[0].Qclass = dns.ClassCHAOS
	resp, _, err := (&dns.Client{Timeout: 2 * time.Second}).Exchange(m, srv.udp)
	if err != nil || resp.Rcode != dns.RcodeRefused || len(resp.Answer) != 0 {
		t.Errorf("class CH: %v, %v", resp, err)
	}
}

func TestServe_TCP(t *testing.T) {
	srv := startServer(t, testConfig())
	expectConfirmed(t, exchange(t, "tcp", srv.tcp, "5.64.249.66.listbot."+zone, dns.TypeA))
	expectNegative(t, exchange(t, "tcp", srv.tcp, "1.2.0.192.listbot."+zone, dns.TypeA), dns.RcodeNameError)
}

func TestServe_PanicGivesServfail(t *testing.T) {
	cfg := testConfig()
	cfg.Store = nil
	srv := startServer(t, cfg)
	if resp := exchange(t, "udp", srv.udp, "5.64.249.66.listbot."+zone, dns.TypeA); resp.Rcode != dns.RcodeServerFailure || len(resp.Answer) != 0 {
		t.Errorf("rcode %s, answers %v; want SERVFAIL", dns.RcodeToString[resp.Rcode], resp.Answer)
	}
}

func TestLimiterTruncates(t *testing.T) {
	cfg := testConfig()
	cfg.Limiter = NewLimiter(1, 1)
	srv := startServer(t, cfg)
	qname := "5.64.249.66.listbot." + zone
	expectConfirmed(t, exchange(t, "udp", srv.udp, qname, dns.TypeA))
	resp := exchange(t, "udp", srv.udp, qname, dns.TypeA)
	if !resp.Truncated || len(resp.Answer)+len(resp.Ns)+len(resp.Extra) != 0 {
		t.Errorf("over the limit: TC %v, sections %v %v %v; want TC and nothing else", resp.Truncated, resp.Answer, resp.Ns, resp.Extra)
	}
	expectConfirmed(t, exchange(t, "tcp", srv.tcp, qname, dns.TypeA))
	if got := srv.handler.Counters().Truncated.Load(); got != 1 {
		t.Errorf("Truncated counter = %d, want 1", got)
	}
}

func TestLimiterKeys(t *testing.T) {
	l := NewLimiter(1, 1)
	at := now
	if !l.Allow(netip.MustParseAddr("2001:db8:0:1::1"), at) || l.Allow(netip.MustParseAddr("2001:db8:0:ff::2"), at) {
		t.Error("addresses in one IPv6 /56 must share a bucket")
	}
	if !l.Allow(netip.MustParseAddr("2001:db8:0:100::1"), at) {
		t.Error("another /56 must have its own bucket")
	}
	if !l.Allow(netip.MustParseAddr("192.0.2.1"), at) || l.Allow(netip.MustParseAddr("192.0.2.200"), at) {
		t.Error("addresses in one IPv4 /24 must share a bucket")
	}
	if !l.Allow(netip.MustParseAddr("192.0.3.1"), at) {
		t.Error("another IPv4 /24 must have its own bucket")
	}
	if l.Allow(netip.MustParseAddr("::ffff:192.0.2.1"), at) {
		t.Error("an IPv4-mapped address must share the IPv4 bucket")
	}
	if !l.Allow(netip.MustParseAddr("192.0.2.1"), at.Add(time.Second)) {
		t.Error("bucket did not refill after one second")
	}
}

func firstAnswer(resp *dns.Msg) dns.RR {
	if len(resp.Answer) == 0 {
		return nil
	}
	return resp.Answer[0]
}

// fillLimiter gives the table maxLimiterEntries distinct IPv6 /56 keys.
func fillLimiter(l *Limiter, at time.Time) {
	for i := range maxLimiterEntries {
		b := [16]byte{0x20, 0x01, 0x0d, 0xb9, byte(i >> 16), byte(i >> 8), byte(i)}
		l.Allow(netip.AddrFrom16(b), at)
	}
}

func TestLimiterKeepsExhaustedSourceWhenFull(t *testing.T) {
	l := NewLimiter(1, 1)
	victim := netip.MustParseAddr("192.0.2.1")
	if !l.Allow(victim, now) || l.Allow(victim, now) {
		t.Fatal("victim bucket not exhausted after its burst")
	}
	fillLimiter(l, now)
	if l.Allow(victim, now) {
		t.Error("a flood of new source keys restored the exhausted victim's burst")
	}
	if l.Allow(netip.MustParseAddr("198.51.100.1"), now) {
		t.Error("a new source was admitted while the table is full of active entries")
	}
}

func TestLimiterEvictsIdleEntriesWhenFull(t *testing.T) {
	l := NewLimiter(1, 1)
	fillLimiter(l, now)
	if !l.Allow(netip.MustParseAddr("198.51.100.1"), now.Add(2*time.Second)) {
		t.Error("a new source was refused although every entry had been idle long enough to refill")
	}
}
