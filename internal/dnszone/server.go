package dnszone

import (
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
)

// TTL is used for positive answers and as the SOA minimum, which resolvers
// use to cache NXDOMAIN and NODATA. It matches the API's Cache-Control.
const TTL = 300

// confirmedAddr is the A record of a confirmed name, DNSBL style.
var confirmedAddr = net.IPv4(127, 0, 0, 2)

// NameServer is one NS of the zone. Addrs are served as glue when the name
// lies inside the zone.
type NameServer struct {
	Name  string
	Addrs []netip.Addr
}

// Config is what the handler answers from.
type Config struct {
	Zone       string
	NS         []NameServer
	Hostmaster string
	Catalog    *catalog.Catalog
	Store      *store.Store
	Now        func() time.Time
	Limiter    *Limiter
}

// Counters are aggregate answer counts. They never include names or clients.
type Counters struct {
	Queries   atomic.Uint64
	Confirmed atomic.Uint64 // NOERROR with the A record
	NoError   atomic.Uint64 // other NOERROR answers: NODATA, apex, glue
	NXDomain  atomic.Uint64
	Refused   atomic.Uint64
	ServFail  atomic.Uint64
	FormErr   atomic.Uint64
	NotImp    atomic.Uint64 // opcodes other than QUERY
	Truncated atomic.Uint64 // rate-limited UDP replies
}

// LogAttrs returns the counters as slog key-value pairs.
func (c *Counters) LogAttrs() []any {
	return []any{"queries", c.Queries.Load(), "confirmed", c.Confirmed.Load(), "noerror", c.NoError.Load(),
		"nxdomain", c.NXDomain.Load(), "refused", c.Refused.Load(), "servfail", c.ServFail.Load(),
		"formerr", c.FormErr.Load(), "notimp", c.NotImp.Load(), "truncated", c.Truncated.Load()}
}

// Handler answers the verify zone authoritatively.
type Handler struct {
	cfg      Config
	zone     string // FQDN, lowercase
	ns       []string
	glue     map[string][]netip.Addr // in-zone NS names
	mbox     string
	counters Counters
}

// NewHandler returns a handler for cfg.
func NewHandler(cfg Config) *Handler {
	h := &Handler{cfg: cfg, zone: fqdnLower(cfg.Zone), mbox: fqdnLower(cfg.Hostmaster), glue: make(map[string][]netip.Addr)}
	for _, ns := range cfg.NS {
		name := fqdnLower(ns.Name)
		h.ns = append(h.ns, name)
		if len(ns.Addrs) > 0 && dns.IsSubDomain(h.zone, name) {
			h.glue[name] = ns.Addrs
		}
	}
	return h
}

// Counters returns the live answer counters.
func (h *Handler) Counters() *Counters { return &h.counters }

func fqdnLower(name string) string {
	return dns.Fqdn(strings.ToLower(name))
}

// ServeDNS implements dns.Handler.
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	h.counters.Queries.Add(1)
	defer func() {
		if recover() != nil {
			m := new(dns.Msg)
			m.SetRcode(req, dns.RcodeServerFailure)
			h.counters.ServFail.Add(1)
			w.WriteMsg(m)
		}
	}()
	udp := isUDP(w)
	if udp && !h.cfg.Limiter.Allow(remoteAddr(w), h.cfg.Now()) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Truncated = true
		h.counters.Truncated.Add(1)
		w.WriteMsg(m)
		return
	}
	m := h.answer(req)
	if udp {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = max(int(opt.UDPSize()), dns.MinMsgSize)
		}
		m.Truncate(size)
	}
	// After Truncate, which turns compression off for replies that fit
	// without it: compressing every reply roughly halves the larger ones,
	// and with them what a spoofed query can reflect.
	m.Compress = true
	w.WriteMsg(m)
}

func (h *Handler) answer(req *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	if req.Opcode != dns.OpcodeQuery {
		m.SetRcode(req, dns.RcodeNotImplemented)
		h.counters.NotImp.Add(1)
		return m
	}
	if len(req.Question) != 1 {
		m.SetRcode(req, dns.RcodeFormatError)
		h.counters.FormErr.Add(1)
		return m
	}
	m.SetReply(req)
	if opt := req.IsEdns0(); opt != nil {
		m.SetEdns0(dns.DefaultMsgSize, false)
	}
	q := req.Question[0]
	if q.Qclass != dns.ClassINET {
		return h.refused(m)
	}
	qname := strings.ToLower(q.Name)
	// Compare wire labels first: ParseName splits the presentation form, in
	// which an escaped dot ("foo\.verify") would look like two labels.
	if !dns.IsSubDomain(h.zone, qname) {
		return h.refused(m)
	}
	if addrs, ok := h.glue[qname]; ok {
		m.Authoritative = true
		m.Answer = glueRecords(qname, addrs, q.Qtype)
		return h.noError(m)
	}

	name := ParseName(qname, h.zone)
	switch name.Kind {
	case Outside:
		return h.refused(m)
	case Apex:
		m.Authoritative = true
		switch q.Qtype {
		case dns.TypeSOA:
			m.Answer = []dns.RR{h.soa()}
		case dns.TypeNS:
			m.Answer = h.nsRecords()
			for _, ns := range h.ns {
				m.Extra = append(m.Extra, glueRecords(ns, h.glue[ns], dns.TypeANY)...)
			}
		}
		return h.noError(m)
	}

	m.Authoritative = true
	switch Decide(h.cfg.Catalog, h.cfg.Store, h.cfg.Now(), name) {
	case AnswerA:
		if q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{Hdr: header(q.Name, dns.TypeA), A: confirmedAddr}}
			h.counters.Confirmed.Add(1)
			return m
		}
		return h.noError(m)
	case AnswerNXDomain:
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{h.soa()}
		h.counters.NXDomain.Add(1)
		return m
	case AnswerRefused:
		return h.refused(m)
	default:
		return h.noError(m)
	}
}

// noError counts a NOERROR reply; one without answers gets the SOA in the
// authority section, which makes it a cacheable NODATA.
func (h *Handler) noError(m *dns.Msg) *dns.Msg {
	if len(m.Answer) == 0 {
		m.Ns = []dns.RR{h.soa()}
	}
	h.counters.NoError.Add(1)
	return m
}

func (h *Handler) refused(m *dns.Msg) *dns.Msg {
	m.Authoritative = false
	m.Rcode = dns.RcodeRefused
	h.counters.Refused.Add(1)
	return m
}

// soa uses the store version as serial. It restarts with the process and
// differs between instances, which is harmless: the zone offers no transfers
// (AXFR/IXFR), so no secondary compares serials.
func (h *Handler) soa() dns.RR {
	serial := uint32(h.cfg.Store.Version())
	if serial == 0 {
		serial = 1
	}
	return &dns.SOA{Hdr: header(h.zone, dns.TypeSOA), Ns: h.ns[0], Mbox: h.mbox, Serial: serial,
		Refresh: 3600, Retry: 600, Expire: 86400, Minttl: TTL}
}

func (h *Handler) nsRecords() []dns.RR {
	out := make([]dns.RR, 0, len(h.ns))
	for _, ns := range h.ns {
		out = append(out, &dns.NS{Hdr: header(h.zone, dns.TypeNS), Ns: ns})
	}
	return out
}

// glueRecords returns the A or AAAA records of an NS name for qtype; ANY
// returns both.
func glueRecords(name string, addrs []netip.Addr, qtype uint16) []dns.RR {
	var out []dns.RR
	for _, addr := range addrs {
		switch {
		case addr.Is4() && (qtype == dns.TypeA || qtype == dns.TypeANY):
			out = append(out, &dns.A{Hdr: header(name, dns.TypeA), A: net.IP(addr.AsSlice())})
		case addr.Is6() && (qtype == dns.TypeAAAA || qtype == dns.TypeANY):
			out = append(out, &dns.AAAA{Hdr: header(name, dns.TypeAAAA), AAAA: net.IP(addr.AsSlice())})
		}
	}
	return out
}

func header(name string, rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: rrtype, Class: dns.ClassINET, Ttl: TTL}
}

func isUDP(w dns.ResponseWriter) bool {
	_, ok := w.RemoteAddr().(*net.UDPAddr)
	return ok
}

func remoteAddr(w dns.ResponseWriter) netip.Addr {
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		ip, _ := netip.AddrFromSlice(addr.IP)
		return ip
	}
	return netip.Addr{}
}
