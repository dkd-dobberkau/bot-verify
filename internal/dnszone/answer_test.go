package dnszone

import (
	"net/netip"
	"testing"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
)

const (
	zone     = "verify.example"
	listURL  = "https://ops.example/list.json"
	list2URL = "https://ops.example/list2.json"
)

var now = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// ipv6Name is the full nibble name of 2001:4860:4801:10::1 under listbot.
const ipv6Name = "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.1.0.8.4.0.6.8.4.1.0.0.2.listbot." + zone

func TestParseName(t *testing.T) {
	cases := []struct {
		qname string
		want  Name
	}{
		{zone, Name{Kind: Apex}},
		{"Verify.Example.", Name{Kind: Apex}},
		{"gptbot." + zone, Name{Kind: BotOnly, Bot: "gptbot"}},
		{"1.66.249.66.gptbot." + zone, Name{Kind: Address, Bot: "gptbot", Addr: netip.MustParseAddr("66.249.66.1")}},
		{"1.66.249.66.GPTBot.Verify.Example.", Name{Kind: Address, Bot: "gptbot", Addr: netip.MustParseAddr("66.249.66.1")}},
		{"0.0.0.10.gptbot." + zone, Name{Kind: Address, Bot: "gptbot", Addr: netip.MustParseAddr("10.0.0.0")}},
		{"1.0.0.2.gptbot." + zone, Name{Kind: Address, Bot: "gptbot", Addr: netip.MustParseAddr("2.0.0.1"), AmbiguousIPv4: true}},
		{"1.0.0.20.gptbot." + zone, Name{Kind: Address, Bot: "gptbot", Addr: netip.MustParseAddr("20.0.0.1")}},
		{ipv6Name, Name{Kind: Address, Bot: "listbot", Addr: netip.MustParseAddr("2001:4860:4801:10::1")}},
		{"2.0.0.0.0.0.0.c.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.listbot." + zone,
			Name{Kind: Address, Bot: "listbot", Addr: netip.MustParseAddr("192.0.0.2")}},
		{"66.gptbot." + zone, Name{Kind: Partial, Bot: "gptbot"}},
		{"249.66.gptbot." + zone, Name{Kind: Partial, Bot: "gptbot"}},
		{"66.249.66.gptbot." + zone, Name{Kind: Partial, Bot: "gptbot"}},
		{"a.b.c.d.gptbot." + zone, Name{Kind: Partial, Bot: "gptbot"}},
		{"0.0.1.0.0.2.gptbot." + zone, Name{Kind: Partial, Bot: "gptbot"}},
		{"256.1.1.1.gptbot." + zone, Name{Kind: Invalid, Bot: "gptbot"}},
		{"01.1.1.1.gptbot." + zone, Name{Kind: Invalid, Bot: "gptbot"}},
		{"x.1.1.1.gptbot." + zone, Name{Kind: Invalid, Bot: "gptbot"}},
		{"1.1.1.1.1.66.gptbot." + zone, Name{Kind: Invalid, Bot: "gptbot"}},
		{"0." + ipv6Name, Name{Kind: Invalid, Bot: "listbot"}},
		{"1..1.1.gptbot." + zone, Name{Kind: Invalid, Bot: "gptbot"}},
		{"example.com.", Name{Kind: Outside}},
		{"notverify.example", Name{Kind: Outside}},
	}
	for _, c := range cases {
		for _, z := range []string{zone, zone + ".", "VERIFY.example."} {
			if got := ParseName(c.qname, z); got != c.want {
				t.Errorf("ParseName(%q, %q) = %+v, want %+v", c.qname, z, got, c.want)
			}
		}
	}
}

func testCatalog() *catalog.Catalog {
	one := []catalog.IPSource{{URL: listURL, Format: "google-prefixes"}}
	return catalog.New([]catalog.Bot{
		{ID: "listbot", Name: "ListBot", IPSources: one},
		{ID: "twobot", Name: "TwoBot", IPSources: append(one, catalog.IPSource{URL: list2URL, Format: "google-prefixes"})},
		{ID: "bothbot", Name: "BothBot", IPSources: one, RDNSSuffixes: []string{"ops.example"}},
		{ID: "dnsbot", Name: "DNSBot", RDNSSuffixes: []string{"ops.example"}},
		{ID: "nobot", Name: "NoBot", NotCheckable: "nothing published"},
	})
}

var listPrefixes = []netip.Prefix{netip.MustParsePrefix("66.249.64.0/27"), netip.MustParsePrefix("2001:4860:4801:10::/64")}

func storeWith(fetchedAt map[string]time.Time) *store.Store {
	st := store.New()
	for url, at := range fetchedAt {
		st.Set(url, store.Snapshot{Prefixes: listPrefixes, FetchedAt: at})
	}
	return st
}

func TestDecide(t *testing.T) {
	fresh := now.Add(-time.Hour)
	stale := now.Add(-store.MaxAge - time.Second)
	allFresh := storeWith(map[string]time.Time{listURL: fresh, list2URL: fresh})
	cases := []struct {
		name  string
		st    *store.Store
		qname string
		want  Answer
	}{
		{"confirmed", allFresh, "5.64.249.66.listbot." + zone, AnswerA},
		{"confirmed ipv6", allFresh, ipv6Name, AnswerA},
		{"refuted, lists only", allFresh, "1.2.0.192.listbot." + zone, AnswerNXDomain},
		{"list not loaded", store.New(), "5.64.249.66.listbot." + zone, AnswerNoData},
		{"list stale, address inside", storeWith(map[string]time.Time{listURL: stale}), "5.64.249.66.listbot." + zone, AnswerNoData},
		{"list stale, address outside", storeWith(map[string]time.Time{listURL: stale}), "1.2.0.192.listbot." + zone, AnswerNoData},
		{"not_checkable bot", allFresh, "1.2.0.192.nobot." + zone, AnswerNoData},
		{"rDNS-only bot", allFresh, "1.2.0.192.dnsbot." + zone, AnswerNoData},
		{"unknown bot", allFresh, "1.2.0.192.ghost." + zone, AnswerNoData},
		{"list and rDNS, list miss", allFresh, "1.2.0.192.bothbot." + zone, AnswerNoData},
		{"list and rDNS, list hit", allFresh, "5.64.249.66.bothbot." + zone, AnswerA},
		{"one list matches, other not loaded", storeWith(map[string]time.Time{listURL: fresh}), "5.64.249.66.twobot." + zone, AnswerA},
		{"one list misses, other not loaded", storeWith(map[string]time.Time{listURL: fresh}), "1.2.0.192.twobot." + zone, AnswerNoData},
		{"apex", allFresh, zone, AnswerNoData},
		{"bot only", allFresh, "listbot." + zone, AnswerNoData},
		{"partial octets", allFresh, "66.listbot." + zone, AnswerNoData},
		{"partial nibbles", allFresh, "0.0.1.0.0.2.listbot." + zone, AnswerNoData},
		{"invalid", allFresh, "256.1.1.1.listbot." + zone, AnswerNXDomain},
		{"outside", allFresh, "example.com.", AnswerRefused},
		{"ambiguous IPv4 refuted gives NODATA", allFresh, "1.0.0.2.listbot." + zone, AnswerNoData},
		{"unambiguous IPv4 refuted gives NXDOMAIN", allFresh, "1.0.0.20.listbot." + zone, AnswerNXDomain},
	}
	cat := testCatalog()
	for _, c := range cases {
		if got := Decide(cat, c.st, now, ParseName(c.qname, zone)); got != c.want {
			t.Errorf("%s: Decide(%q) = %v, want %v", c.name, c.qname, got, c.want)
		}
	}
}

func TestDecideNeverAOnStaleOrMissing(t *testing.T) {
	cat := testCatalog()
	states := map[string]*store.Store{
		"not loaded": store.New(),
		"stale":      storeWith(map[string]time.Time{listURL: now.Add(-store.MaxAge - time.Second), list2URL: now.Add(-store.MaxAge - time.Second)}),
	}
	for stateName, st := range states {
		for _, bot := range cat.Bots {
			for _, rev := range []string{"5.64.249.66", "1.2.0.192", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.1.0.8.4.0.6.8.4.1.0.0.2"} {
				qname := rev + "." + bot.ID + "." + zone
				if got := Decide(cat, st, now, ParseName(qname, zone)); got == AnswerA {
					t.Errorf("%s, %s: Decide(%q) = A", stateName, bot.ID, qname)
				}
			}
		}
	}
}
