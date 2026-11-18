package rdns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fixtureDNS is a minimal loopback UDP DNS server, so tests can drive the real
// pure-Go net.Resolver through failure modes a fake Resolver cannot imitate.
// It knows one PTR (fixtureIP -> fixtureHost); A and AAAA answers are set per test.
type fixtureDNS struct {
	conn    net.PacketConn
	aRcode  atomic.Int32 // 0 = answer fixtureIP, 2 = SERVFAIL
	queries atomic.Int32
}

const (
	fixtureIP     = "66.249.66.1"
	fixtureHost   = "crawl-66-249-66-1.googlebot.com."
	fixturePTR    = "1.66.249.66.in-addr.arpa."
	rcodeServFail = 2
	rcodeNXDomain = 3
	typeA         = 1
	typePTR       = 12
	typeAAAA      = 28
)

// newFixtureDNS starts the server and returns a real resolver that talks only to it.
func newFixtureDNS(t *testing.T) (*fixtureDNS, *net.Resolver) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	d := &fixtureDNS{conn: conn}
	go d.serve()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "udp", conn.LocalAddr().String())
		},
	}
	return d, resolver
}

func (d *fixtureDNS) serve() {
	buf := make([]byte, 1500)
	for {
		n, addr, err := d.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		d.queries.Add(1)
		go d.answer(append([]byte(nil), buf[:n]...), addr)
	}
}

func (d *fixtureDNS) answer(query []byte, addr net.Addr) {
	name, qtype, end := parseQuestion(query)
	var rcode uint16
	var record []byte
	switch {
	case name == fixturePTR && qtype == typePTR:
		record = resourceRecord(typePTR, encodeName(fixtureHost))
	case name == fixtureHost && qtype == typeA:
		if code := d.aRcode.Load(); code != 0 {
			// Answer A late, so a merged A+AAAA lookup sees AAAA NODATA first.
			time.Sleep(150 * time.Millisecond)
			rcode = uint16(code)
		} else {
			record = resourceRecord(typeA, netip.MustParseAddr(fixtureIP).AsSlice())
		}
	case name == fixtureHost && qtype == typeAAAA:
		// NOERROR with no answer (NODATA): the host is IPv4-only.
	default:
		rcode = rcodeNXDomain
	}
	resp := append([]byte(nil), query[:end]...)
	recursionDesired := binary.BigEndian.Uint16(query[2:]) & 0x0100
	binary.BigEndian.PutUint16(resp[2:], 0x8000|recursionDesired|0x0080|rcode)
	ancount := uint16(0)
	if record != nil {
		ancount = 1
	}
	binary.BigEndian.PutUint16(resp[6:], ancount)
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)
	d.conn.WriteTo(append(resp, record...), addr)
}

func parseQuestion(msg []byte) (name string, qtype uint16, end int) {
	i := 12
	var labels []string
	for msg[i] != 0 {
		length := int(msg[i])
		labels = append(labels, string(msg[i+1:i+1+length]))
		i += 1 + length
	}
	i++
	return strings.ToLower(strings.Join(labels, ".")) + ".", binary.BigEndian.Uint16(msg[i:]), i + 4
}

func encodeName(name string) []byte {
	var out []byte
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// resourceRecord answers the question name (compression pointer to offset 12).
func resourceRecord(rtype uint16, data []byte) []byte {
	rr := []byte{0xc0, 12}
	rr = binary.BigEndian.AppendUint16(rr, rtype)
	rr = binary.BigEndian.AppendUint16(rr, 1) // class IN
	rr = binary.BigEndian.AppendUint32(rr, 60)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(data)))
	return append(rr, data...)
}

func TestRealResolverForwardConfirms(t *testing.T) {
	_, resolver := newFixtureDNS(t)
	now := t0
	outcome, host, err := newChecker(resolver, &now).Check(context.Background(), netip.MustParseAddr(fixtureIP), []string{"googlebot.com"})
	if err != nil || outcome != Match || host != "crawl-66-249-66-1.googlebot.com" {
		t.Errorf("got %v %q %v, want Match", outcome, host, err)
	}
}

// A SERVFAIL on the A record must not be hidden by the AAAA NODATA answer:
// Go's merged A+AAAA lookup reports that as "no such host", which looked like
// a definite no and produced a cached false refuted for a real crawler.
func TestRealResolverTransientARecordIsLookupError(t *testing.T) {
	dns, resolver := newFixtureDNS(t)
	dns.aRcode.Store(rcodeServFail)
	now := t0
	checker := newChecker(resolver, &now)
	ip := netip.MustParseAddr(fixtureIP)
	_, _, err := checker.Check(context.Background(), ip, []string{"googlebot.com"})
	if !errors.Is(err, ErrLookup) {
		t.Fatalf("err = %v, want ErrLookup", err)
	}
	dns.aRcode.Store(0)
	before := dns.queries.Load()
	outcome, _, err := checker.Check(context.Background(), ip, []string{"googlebot.com"})
	if err != nil || outcome != Match {
		t.Errorf("after recovery: %v %v, want Match", outcome, err)
	}
	if dns.queries.Load() == before {
		t.Error("answer after recovery came from cache; the failure must not be cached")
	}
}
