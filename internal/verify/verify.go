// Package verify answers "is this IP really this bot?" from the operator's
// published IP lists and reverse-DNS rule.
package verify

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/rdns"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
)

// Verdicts and methods, as they appear in the API.
const (
	Confirmed    = "confirmed"
	Refuted      = "refuted"
	NotCheckable = "not_checkable"

	MethodIPList = "ip_list"
	MethodRDNS   = "rdns"
	MethodNone   = "none"

	ReasonDNSFailed = "dns lookup failed"
	ReasonNotLoaded = "source data not loaded"
)

// ErrUnknownBot means the bot id is not in the catalog.
var ErrUnknownBot = errors.New("unknown bot")

// RDNS is the reverse-DNS check the verifier needs (rdns.Checker).
type RDNS interface {
	Check(ctx context.Context, ip netip.Addr, suffixes []string) (rdns.Outcome, string, error)
}

// Result is one verdict. Sources lists the operator URLs it rests on.
type Result struct {
	IP             string   `json:"ip"`
	Bot            string   `json:"bot"`
	Result         string   `json:"result"`
	Method         string   `json:"method"`
	Reason         string   `json:"reason,omitempty"`
	Hostname       string   `json:"hostname,omitempty"`
	Sources        []string `json:"sources"`
	DataAgeSeconds *int64   `json:"data_age_seconds,omitempty"`
}

// Verifier combines catalog, store and reverse DNS.
type Verifier struct {
	catalog *catalog.Catalog
	store   *store.Store
	rdns    RDNS
	now     func() time.Time
}

// New returns a verifier.
func New(cat *catalog.Catalog, st *store.Store, r RDNS, now func() time.Time) *Verifier {
	return &Verifier{catalog: cat, store: st, rdns: r, now: now}
}

// Verify checks IP lists first, then reverse DNS. Anything that is not a
// definite answer gives not_checkable, never refuted.
func (v *Verifier) Verify(ctx context.Context, ip netip.Addr, botID string) (Result, error) {
	ip = ip.Unmap()
	bot, ok := v.catalog.Get(botID)
	if !ok {
		return Result{}, ErrUnknownBot
	}
	res := Result{IP: ip.String(), Bot: bot.ID, Sources: sourcesOf(bot)}
	verdict := func(result, method, reason string) Result {
		res.Result, res.Method, res.Reason = result, method, reason
		return res
	}
	if !bot.Checkable() {
		return verdict(NotCheckable, MethodNone, bot.NotCheckable), nil
	}

	allLoaded := true
	var oldest time.Time
	for _, src := range bot.IPSources {
		matched, loaded, fetchedAt := v.store.Contains(src.URL, ip)
		if matched {
			res.DataAgeSeconds = v.ageSeconds(fetchedAt)
			return verdict(Confirmed, MethodIPList, ""), nil
		}
		if !loaded {
			allLoaded = false
		} else if oldest.IsZero() || fetchedAt.Before(oldest) {
			oldest = fetchedAt
		}
	}
	if !oldest.IsZero() {
		res.DataAgeSeconds = v.ageSeconds(oldest)
	}

	if len(bot.RDNSSuffixes) > 0 {
		outcome, hostname, err := v.rdns.Check(ctx, ip, bot.RDNSSuffixes)
		switch {
		case err != nil:
			return verdict(NotCheckable, MethodRDNS, ReasonDNSFailed), nil
		case outcome == rdns.Match:
			res.Hostname = hostname
			return verdict(Confirmed, MethodRDNS, ""), nil
		}
		// An operator's rDNS rule may not cover all its addresses (CCBot:
		// IPv4 only), so a NoMatch refutes only once every list is loaded.
		if allLoaded {
			return verdict(Refuted, MethodRDNS, ""), nil
		}
	}
	if !allLoaded {
		return verdict(NotCheckable, MethodIPList, ReasonNotLoaded), nil
	}
	return verdict(Refuted, MethodIPList, ""), nil
}

func (v *Verifier) ageSeconds(fetchedAt time.Time) *int64 {
	age := int64(v.now().Sub(fetchedAt).Seconds())
	return &age
}

func sourcesOf(bot catalog.Bot) []string {
	out := make([]string, 0, len(bot.IPSources)+1)
	for _, src := range bot.IPSources {
		out = append(out, src.URL)
	}
	if bot.Docs != "" {
		out = append(out, bot.Docs)
	}
	return out
}
