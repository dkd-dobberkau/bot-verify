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

// carrierGradeNAT is shared address space (RFC 6598), not reachable publicly.
var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

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
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !carrierGradeNAT.Contains(addr)
}
