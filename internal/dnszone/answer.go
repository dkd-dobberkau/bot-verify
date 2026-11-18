// Package dnszone answers the verify zone: "<reversed address>.<bot-id>.<zone>"
// resolves to 127.0.0.2 when a loaded, fresh operator list of the bot holds
// the address. The rules are in docs/verdicts.md.
package dnszone

import (
	"net/netip"
	"strings"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
)

// Kind is what a query name is, relative to the zone.
type Kind int

const (
	Apex    Kind = iota // the zone itself
	BotOnly             // <bot-id>.<zone>
	Partial             // above a complete address: some octets or nibbles
	Address             // a complete reversed address
	Invalid             // inside the zone, but nothing valid exists below it
	Outside             // not in the zone
)

// Name is a parsed query name. AmbiguousIPv4 marks an IPv4 name whose labels
// are all single digits: it is also a prefix of IPv6 nibble names.
type Name struct {
	Kind          Kind
	Bot           string
	Addr          netip.Addr
	AmbiguousIPv4 bool
}

// ParseName reads qname relative to zone, ignoring case and trailing dots.
func ParseName(qname, zone string) Name {
	qname = normalize(qname)
	zone = normalize(zone)
	if qname == zone {
		return Name{Kind: Apex}
	}
	rest, ok := strings.CutSuffix(qname, "."+zone)
	if !ok {
		return Name{Kind: Outside}
	}
	labels := strings.Split(rest, ".")
	n := Name{Bot: labels[len(labels)-1]}
	addr := labels[:len(labels)-1]
	switch {
	case n.Bot == "":
		n.Kind = Invalid
	case len(addr) == 0:
		n.Kind = BotOnly
	case len(addr) == 4 && all(addr, isOctet):
		n.Kind, n.Addr = Address, ipv4From(addr)
		n.AmbiguousIPv4 = all(addr, isDigitNibble)
	case len(addr) == 32 && all(addr, isNibble):
		n.Kind, n.Addr = Address, ipv6From(addr).Unmap()
	case len(addr) < 4 && all(addr, isOctet), len(addr) < 32 && all(addr, isNibble):
		n.Kind = Partial
	default:
		n.Kind = Invalid
	}
	return n
}

func normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

func all(labels []string, ok func(string) bool) bool {
	for _, label := range labels {
		if !ok(label) {
			return false
		}
	}
	return true
}

// isOctet accepts 0-255 in decimal without leading zeros.
func isOctet(label string) bool {
	if label == "" || len(label) > 3 || (len(label) > 1 && label[0] == '0') {
		return false
	}
	value := 0
	for _, c := range label {
		if c < '0' || c > '9' {
			return false
		}
		value = value*10 + int(c-'0')
	}
	return value <= 255
}

func isNibble(label string) bool {
	return len(label) == 1 && strings.ContainsRune("0123456789abcdef", rune(label[0]))
}

func isDigitNibble(label string) bool {
	return len(label) == 1 && label[0] >= '0' && label[0] <= '9'
}

// ipv4From reads reversed octets that passed isOctet.
func ipv4From(labels []string) netip.Addr {
	var b [4]byte
	for i, label := range labels {
		value := 0
		for _, c := range label {
			value = value*10 + int(c-'0')
		}
		b[3-i] = byte(value)
	}
	return netip.AddrFrom4(b)
}

// ipv6From reads 32 reversed nibbles that passed isNibble.
func ipv6From(labels []string) netip.Addr {
	var b [16]byte
	for i, label := range labels {
		nibble := byte(strings.IndexByte("0123456789abcdef", label[0]))
		pos := 31 - i
		if pos%2 == 0 {
			b[pos/2] |= nibble << 4
		} else {
			b[pos/2] |= nibble
		}
	}
	return netip.AddrFrom16(b)
}

// Answer is the response a name gets.
type Answer int

const (
	AnswerA        Answer = iota // confirmed: A 127.0.0.2
	AnswerNXDomain               // refuted, or nothing valid below the name
	AnswerNoData                 // not checkable, or a name above an address
	AnswerRefused                // not in the zone
)

// Decide gives the answer for a parsed name. An A answer needs a match in a
// loaded, fresh list; NXDOMAIN needs every list loaded and fresh, no other
// way for the bot to be verified, and no valid name below the queried one.
func Decide(cat *catalog.Catalog, st *store.Store, now time.Time, n Name) Answer {
	switch n.Kind {
	case Outside:
		return AnswerRefused
	case Invalid:
		return AnswerNXDomain
	case Address:
	default:
		return AnswerNoData
	}
	bot, ok := cat.Get(n.Bot)
	if !ok || !bot.Checkable() || len(bot.IPSources) == 0 {
		return AnswerNoData
	}
	allFresh := true
	for _, src := range bot.IPSources {
		state, matched, _ := st.Lookup(src.URL, n.Addr, now)
		if matched {
			return AnswerA
		}
		if state != store.Loaded {
			allFresh = false
		}
	}
	// Reverse DNS might still confirm the address, so a list miss is no
	// refutation for a bot that has suffixes too.
	if !allFresh || len(bot.RDNSSuffixes) > 0 || n.AmbiguousIPv4 {
		return AnswerNoData
	}
	return AnswerNXDomain
}
