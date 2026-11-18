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
// It knows one PTR (fixtureIP -> fixtureHost); the PTR and A answers are set per test.
type fixtureDNS struct {
	conn    net.PacketConn
	aRcode  atomic.Int32 // 0 = answer fixtureIP, 2 = SERVFAIL
	ptrMode atomic.Value // one of the ptr* modes below; "" answers the PTR
	queries atomic.Int32
}

// PTR failure modes. Over TCP the fixture refuses connections, so a truncated
// UDP answer cannot be completed.
const (
	ptrServFail  = "servfail"  // SERVFAIL
	ptrNoData    = "nodata"    // NOERROR without answer: no PTR exists
	ptrLame      = "lame"      // NOERROR, no answer, recursion not available, NS in authority
	ptrTruncated = "truncated" // TC bit set, no answer
	ptrMalformed = "malformed" // one valid and one invalid name
	ptrDrop      = "drop"      // no answer at all
)

const (
	fixtureIP     = "66.249.66.1"
	fixtureHost   = "crawl-66-249-66-1.googlebot.com."
	fixturePTR    = "1.66.249.66.in-addr.arpa."
	rcodeServFail = 2
	rcodeNXDomain = 3
	typeA         = 1
	typeNS        = 2
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
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refusing := closed.Addr().String()
	closed.Close()
	d := &fixtureDNS{conn: conn}
	d.ptrMode.Store("")
	go d.serve()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			if strings.HasPrefix(network, "tcp") {
				return dialer.DialContext(ctx, "tcp", refusing)
			}
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
	var answers [][]byte
	var authority []byte
	recursionAvailable, truncated := true, false
	switch {
	case name == fixturePTR && qtype == typePTR:
		switch d.ptrMode.Load().(string) {
		case ptrServFail:
			rcode = rcodeServFail
		case ptrNoData:
		case ptrLame:
			recursionAvailable = false
			authority = resourceRecord(typeNS, encodeName("ns.example."))
		case ptrTruncated:
			truncated = true
		case ptrMalformed:
			answers = append(answers, resourceRecord(typePTR, encodeName(fixtureHost)),
				resourceRecord(typePTR, encodeName("bad name.example.")))
		case ptrDrop:
			return
		default:
			answers = append(answers, resourceRecord(typePTR, encodeName(fixtureHost)))
		}
	case name == fixtureHost && qtype == typeA:
		if code := d.aRcode.Load(); code != 0 {
			// Answer A late, so a merged A+AAAA lookup sees AAAA NODATA first.
			time.Sleep(150 * time.Millisecond)
			rcode = uint16(code)
		} else {
			answers = append(answers, resourceRecord(typeA, netip.MustParseAddr(fixtureIP).AsSlice()))
		}
	case name == fixtureHost && qtype == typeAAAA:
		// NOERROR with no answer (NODATA): the host is IPv4-only.
	default:
		rcode = rcodeNXDomain
	}
	resp := append([]byte(nil), query[:end]...)
	flags := 0x8000 | binary.BigEndian.Uint16(query[2:])&0x0100 | rcode
	if recursionAvailable {
		flags |= 0x0080
	}
	if truncated {
		flags |= 0x0200
	}
	binary.BigEndian.PutUint16(resp[2:], flags)
	binary.BigEndian.PutUint16(resp[6:], uint16(len(answers)))
	nscount := uint16(0)
	if authority != nil {
		nscount = 1
	}
	binary.BigEndian.PutUint16(resp[8:], nscount)
	binary.BigEndian.PutUint16(resp[10:], 0)
	for _, rr := range answers {
		resp = append(resp, rr...)
	}
	d.conn.WriteTo(append(resp, authority...), addr)
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

// TestRealResolverPTRFailureModes pins how each PTR failure is classified.
// Only an answer that says "no PTR exists" may become NoMatch (and so
// refuted); everything that leaves the question open must be ErrLookup.
func TestRealResolverPTRFailureModes(t *testing.T) {
	cases := map[string]bool{ // mode -> definite NoMatch expected
		ptrNoData:    true,
		ptrServFail:  false,
		ptrLame:      false,
		ptrTruncated: false,
		ptrMalformed: false,
		ptrDrop:      false,
	}
	for mode, definite := range cases {
		t.Run(mode, func(t *testing.T) {
			dns, resolver := newFixtureDNS(t)
			dns.ptrMode.Store(mode)
			now := t0
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			outcome, _, err := newChecker(resolver, &now).Check(ctx, netip.MustParseAddr(fixtureIP), []string{"googlebot.com"})
			if definite {
				if err != nil || outcome != NoMatch {
					t.Errorf("got %v %v, want definite NoMatch", outcome, err)
				}
				return
			}
			if !errors.Is(err, ErrLookup) {
				t.Errorf("got %v %v, want ErrLookup", outcome, err)
			}
		})
	}
}
