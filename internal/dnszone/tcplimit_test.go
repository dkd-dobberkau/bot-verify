package dnszone

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startLimitedTCP serves testConfig over TCP behind LimitListener.
func startLimitedTCP(t *testing.T, total, perSource int) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: LimitListener(ln, total, perSource), Handler: NewHandler(testConfig())}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go srv.ActivateAndServe()
	<-started
	t.Cleanup(func() { srv.Shutdown() })
	return ln.Addr().String()
}

// dialAnswered opens a TCP connection and checks it gets a confirmed answer.
func dialAnswered(t *testing.T, addr string) *dns.Conn {
	t.Helper()
	conn, err := dns.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !answers(conn) {
		t.Fatal("connection within the limits got no answer")
	}
	return conn
}

func answers(conn *dns.Conn) bool {
	m := new(dns.Msg)
	m.SetQuestion("5.64.249.66.listbot."+zone+".", dns.TypeA)
	conn.SetDeadline(time.Now().Add(time.Second))
	if err := conn.WriteMsg(m); err != nil {
		return false
	}
	resp, err := conn.ReadMsg()
	return err == nil && len(resp.Answer) == 1
}

func TestLimitListenerCapsConnectionsPerSource(t *testing.T) {
	addr := startLimitedTCP(t, 10, 2)
	first, second := dialAnswered(t, addr), dialAnswered(t, addr)
	defer first.Close()
	defer second.Close()
	third, err := dns.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		defer third.Close()
		if answers(third) {
			t.Error("a third connection from the same source was served with a per-source cap of 2")
		}
	}
	if !answers(first) {
		t.Error("an existing connection stopped being served")
	}
}

func TestLimitListenerCapsTotalAndReleasesSlots(t *testing.T) {
	addr := startLimitedTCP(t, 1, 10)
	first := dialAnswered(t, addr)
	extra, err := dns.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		if answers(extra) {
			t.Error("a second connection was served with a total cap of 1")
		}
		extra.Close()
	}
	first.Close()
	var again *dns.Conn
	for deadline := time.Now().Add(2 * time.Second); again == nil; time.Sleep(20 * time.Millisecond) {
		if conn, err := dns.DialTimeout("tcp", addr, time.Second); err == nil {
			if answers(conn) {
				again = conn
			} else {
				conn.Close()
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the slot of a closed connection was not released")
		}
	}
	again.Close()
}
