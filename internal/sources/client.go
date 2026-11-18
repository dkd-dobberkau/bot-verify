package sources

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// nonPublic lists special-purpose ranges that netip counts as global
// unicast but that are not the public internet (RFC 6890 registry).
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
}

// Translation prefixes that carry an IPv4 address: on a network with NAT64 or
// a 6to4 relay, connecting to them reaches that IPv4 address.
var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

// NewClient returns the HTTP client for operator sources. It refuses https to
// http redirects, and it refuses to connect to non-public addresses, so a
// listed origin cannot point the fetcher at loopback, private or metadata
// endpoints, by redirect or by DNS. The address check runs after DNS
// resolution. When an outbound proxy is configured in the environment, the
// client connects to the proxy instead, and the proxy owns egress policy.
func NewClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if !proxyConfigured() {
		dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: refuseNonPublic}
		transport.DialContext = dialer.DialContext
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: RejectDowngrade}
}

func proxyConfigured() bool {
	proxy, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: "example.com"}})
	return err != nil || proxy != nil
}

func refuseNonPublic(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("refusing connection to %s: %w", address, err)
	}
	if !isPublicAddr(addrPort.Addr()) {
		return fmt.Errorf("refusing connection to non-public address %s", addrPort.Addr())
	}
	return nil
}

func isPublicAddr(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublic {
		if prefix.Contains(addr) {
			return false
		}
	}
	if embedded, ok := embeddedIPv4(addr); ok {
		return isPublicAddr(embedded)
	}
	return true
}

// embeddedIPv4 returns the IPv4 address a NAT64 (RFC 6052) or 6to4
// (RFC 3056) address leads to.
func embeddedIPv4(addr netip.Addr) (netip.Addr, bool) {
	b := addr.As16()
	switch {
	case nat64.Contains(addr):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}
