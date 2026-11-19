package api

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/dkd-dobberkau/bot-verify/internal/ratelimit"
)

// ClientLimit limits requests per client network. The zero value limits
// nothing.
type ClientLimit struct {
	Limiter *ratelimit.Limiter
	// TrustedProxies are the networks of the reverse proxies in front of the
	// API. Only a peer inside them may name the client in X-Forwarded-For.
	TrustedProxies []netip.Prefix
	Now            func() time.Time
}

// limitClients answers 429 to a client network over its rate. The health
// endpoints stay open: the container health check and the host's probes use
// them.
func limitClients(limit ClientLimit, next http.Handler) http.Handler {
	if limit.Limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			client, ok := clientAddr(r, limit.TrustedProxies)
			if !ok || !limit.Limiter.Allow(client, limit.Now()) {
				// The rate is a whole number per second, so one token is back
				// within a second.
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests from your network; retry later")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// clientAddr is the TCP peer, unless the peer is a trusted proxy. Then
// X-Forwarded-For is read from the right, past further trusted hops, and the
// first other address is the client: entries to its left were written by the
// client and are never used. A malformed entry ends the walk at the last
// trusted hop, which then counts as the client.
func clientAddr(r *http.Request, trusted []netip.Prefix) (netip.Addr, bool) {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, false
	}
	client := peer.Addr().Unmap()
	if !inAny(client, trusted) {
		return client, true
	}
	var hops []string
	for _, header := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(header, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil || hop.Zone() != "" {
			break
		}
		client = hop.Unmap()
		if !inAny(client, trusted) {
			break
		}
	}
	return client, true
}

func inAny(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
