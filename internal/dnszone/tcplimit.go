package dnszone

import (
	"net"
	"net/netip"
	"sync"
)

// LimitListener caps concurrent TCP connections, in total and per source
// (IPv4 address or IPv6 /56). TCP is the fallback the UDP limiter sends
// resolvers to, so it must not be exhaustible by one client: a connection
// over either cap is closed as soon as it is accepted.
func LimitListener(ln net.Listener, total, perSource int) net.Listener {
	return &limitListener{Listener: ln, total: total, perSource: perSource, bySource: make(map[netip.Addr]int)}
}

type limitListener struct {
	net.Listener
	total, perSource int

	mu       sync.Mutex
	open     int
	bySource map[netip.Addr]int
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key := connKey(conn.RemoteAddr())
		if !l.acquire(key) {
			conn.Close()
			continue
		}
		return &limitedConn{Conn: conn, release: func() { l.release(key) }}, nil
	}
}

func (l *limitListener) acquire(key netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open >= l.total || l.bySource[key] >= l.perSource {
		return false
	}
	l.open++
	l.bySource[key]++
	return true
}

func (l *limitListener) release(key netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.open--
	if l.bySource[key]--; l.bySource[key] == 0 {
		delete(l.bySource, key)
	}
}

// limitedConn gives its slot back on the first Close.
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// connKey is the per-source key of a TCP peer. TCP sources cannot be
// spoofed, so IPv4 is keyed per address; IPv6 per /56 like the UDP limiter.
func connKey(addr net.Addr) netip.Addr {
	tcp, ok := addr.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}
	}
	ip, _ := netip.AddrFromSlice(tcp.IP)
	ip = ip.Unmap()
	if ip.Is4() {
		return ip
	}
	prefix, _ := ip.WithZone("").Prefix(56)
	return prefix.Addr()
}
