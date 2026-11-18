// Command bot-verify-dns collects bot operators' published IP lists and
// answers "is this IP really this bot?" as an authoritative DNS zone:
// <reversed address>.<bot-id>.<zone> resolves to 127.0.0.2 when confirmed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"github.com/dkd-dobberkau/bot-verify/internal/catalog"
	"github.com/dkd-dobberkau/bot-verify/internal/dnszone"
	"github.com/dkd-dobberkau/bot-verify/internal/snapshot"
	"github.com/dkd-dobberkau/bot-verify/internal/sources"
	"github.com/dkd-dobberkau/bot-verify/internal/store"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

// newFetchClient builds the client for operator sources; tests replace it.
var newFetchClient = func() *http.Client { return sources.NewClient(30 * time.Second) }

// Per-source limits: a resolver serving many clients stays far below them,
// a reflection flood is answered with empty truncated replies.
const (
	rateLimit      = 200
	rateBurst      = 400
	countersPeriod = 10 * time.Minute
)

// A TCP connection is the fallback for rate-limited resolvers. These bound
// how long one anonymous client can hold it: miekg's defaults are 8 s idle
// and 128 queries per connection.
const (
	tcpIdleTimeout = 2 * time.Second
	tcpMaxQueries  = 32
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bot-verify-dns:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("bot-verify-dns", flag.ContinueOnError)
	listen := flags.String("listen", ":5353", "UDP and TCP listen address")
	botsPath := flags.String("bots", "bots.yaml", "bot catalog file")
	zone := flags.String("zone", "", "zone name, e.g. verify.example (required)")
	var nameServers nsFlag
	flags.Var(&nameServers, "ns", "name server of the zone, as name or name=ip[,ip] for in-zone glue (repeatable, at least one)")
	hostmaster := flags.String("hostmaster", "", "SOA mailbox as a domain name, e.g. hostmaster.verify.example (required)")
	refresh := flags.Duration("refresh", 6*time.Hour, "interval between source refreshes")
	snapshotPath := flags.String("snapshot", "", "JSONL file to keep the lists in for a warm start (off when empty)")
	tcpMaxConns := flags.Int("tcp-max-conns", 512, "maximum concurrent TCP connections")
	tcpMaxPerSource := flags.Int("tcp-max-per-source", 16, "maximum concurrent TCP connections per IPv4 address or IPv6 /56")
	showVersion := flags.Bool("version", false, "print version and exit")
	probe := flags.Bool("probe", false, "query the server at -listen and exit (container health check)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintln(stdout, "bot-verify-dns", version)
		return nil
	}
	if *probe {
		return probeServer(*listen, *zone)
	}
	if err := checkFlags(*zone, nameServers, *hostmaster, *refresh, *tcpMaxConns, *tcpMaxPerSource); err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	sources.UserAgent = "bot-verify-dns/" + version + " (+https://github.com/dkd-dobberkau/bot-verify)"
	cat, err := catalog.Load(*botsPath, sources.KnownFormat)
	if err != nil {
		return err
	}
	if err := checkNSLabels(*zone, nameServers, cat); err != nil {
		return err
	}

	st := store.New()
	persist := snapshot.Keep(*snapshotPath, cat, st, logger)
	client := newFetchClient()
	go store.RunScheduler(ctx, *refresh, func(ctx context.Context) {
		errs := store.Refresh(ctx, cat, client, st, time.Now)
		for _, err := range errs {
			logger.Warn("source refresh failed", "error", err.Error())
		}
		logger.Info("sources refreshed", "failed", len(errs))
		persist()
	})

	handler := dnszone.NewHandler(dnszone.Config{Zone: *zone, NS: nameServers, Hostmaster: *hostmaster,
		Catalog: cat, Store: st, Now: time.Now, Limiter: dnszone.NewLimiter(rateLimit, rateBurst)})
	pc, ln, err := listenBoth(*listen)
	if err != nil {
		return err
	}
	servers := []*dns.Server{
		{PacketConn: pc, Handler: handler},
		{Listener: dnszone.LimitListener(ln, *tcpMaxConns, *tcpMaxPerSource), Handler: handler,
			IdleTimeout: func() time.Duration { return tcpIdleTimeout }, MaxTCPQueries: tcpMaxQueries},
	}
	serveErr := make(chan error, len(servers))
	for _, srv := range servers {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { serveErr <- srv.ActivateAndServe() }()
		select {
		case <-started:
		case err := <-serveErr:
			return err
		}
	}
	fmt.Fprintf(stdout, "listening on %s\n", pc.LocalAddr())

	ticker := time.NewTicker(countersPeriod)
	defer ticker.Stop()
	for running := true; running; {
		select {
		case err := <-serveErr:
			return err
		case <-ticker.C:
			logger.Info("dns answers", handler.Counters().LogAttrs()...)
		case <-ctx.Done():
			running = false
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var errs []error
	for _, srv := range servers {
		errs = append(errs, srv.ShutdownContext(shutdownCtx))
	}
	logger.Info("dns answers", handler.Counters().LogAttrs()...)
	return errors.Join(errs...)
}

func checkFlags(zone string, nameServers nsFlag, hostmaster string, refresh time.Duration, tcpMaxConns, tcpMaxPerSource int) error {
	if !validDomain(zone) {
		return fmt.Errorf("-zone %q is not a valid domain name", zone)
	}
	if len(nameServers) == 0 {
		return errors.New("-ns is required at least once")
	}
	if !validDomain(hostmaster) {
		return fmt.Errorf("-hostmaster %q is not a valid domain name", hostmaster)
	}
	if refresh <= 0 {
		return errors.New("-refresh must be positive")
	}
	if tcpMaxConns <= 0 || tcpMaxPerSource <= 0 {
		return errors.New("-tcp-max-conns and -tcp-max-per-source must be positive")
	}
	return nil
}

// domainPattern is a host name of letters, digits and hyphens, with an
// optional trailing dot. dns.IsDomainName accepts any bytes in a label.
var domainPattern = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$`)

func validDomain(name string) bool {
	return len(name) <= 253 && domainPattern.MatchString(name)
}

// checkNSLabels rejects in-zone NS names the zone cannot serve: the apex
// (glue would replace its SOA and NS answers), a name without addresses
// (the zone would answer NODATA for its own name server), and a name whose
// label next to the zone is a bot id (glue would shadow that bot's names).
func checkNSLabels(zone string, nameServers nsFlag, cat *catalog.Catalog) error {
	for _, ns := range nameServers {
		name := dnszone.ParseName(ns.Name, zone)
		switch {
		case name.Kind == dnszone.Outside:
			continue
		case name.Kind == dnszone.Apex:
			return fmt.Errorf("-ns %s: the zone apex cannot be a name server name", ns.Name)
		case len(ns.Addrs) == 0:
			return fmt.Errorf("-ns %s: a name server inside the zone needs its addresses (name=ip[,ip])", ns.Name)
		case hasInvalidAncestor(ns.Name, zone):
			// The zone would answer NXDOMAIN for that ancestor, which tells
			// RFC 8020 resolvers the name server's own name does not exist.
			return fmt.Errorf("-ns %s: a name between it and the zone cannot exist in the zone", ns.Name)
		case name.Bot == "":
			continue
		}
		if _, ok := cat.Get(name.Bot); ok {
			return fmt.Errorf("-ns %s: label %q is a bot id in the catalog", ns.Name, name.Bot)
		}
	}
	return nil
}

// hasInvalidAncestor reports whether a name between name and zone parses
// as Invalid, the kind the zone answers with NXDOMAIN.
func hasInvalidAncestor(name, zone string) bool {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i := 1; i < len(labels); i++ {
		ancestor := strings.Join(labels[i:], ".")
		if parsed := dnszone.ParseName(ancestor, zone); parsed.Kind == dnszone.Invalid {
			return true
		}
	}
	return false
}

// nsFlag collects repeated -ns name[=ip[,ip]] values.
type nsFlag []dnszone.NameServer

func (f *nsFlag) String() string { return fmt.Sprint(*f) }

func (f *nsFlag) Set(value string) error {
	name, addrList, hasAddrs := strings.Cut(value, "=")
	if !validDomain(name) {
		return fmt.Errorf("%q is not a valid domain name", name)
	}
	ns := dnszone.NameServer{Name: name}
	if hasAddrs {
		for _, text := range strings.Split(addrList, ",") {
			addr, err := netip.ParseAddr(text)
			if err != nil || addr.Zone() != "" {
				return fmt.Errorf("%q is not an IP address", text)
			}
			ns.Addrs = append(ns.Addrs, addr.Unmap())
		}
	}
	*f = append(*f, ns)
	return nil
}

// listenBoth opens UDP and TCP on the same address. With port 0, the TCP
// port follows the one the system picked for UDP, retried if it is taken.
func listenBoth(addr string) (net.PacketConn, net.Listener, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, nil, err
	}
	for attempt := 0; ; attempt++ {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return nil, nil, err
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, ln, nil
		}
		pc.Close()
		if port != "0" || attempt == 9 {
			return nil, nil, err
		}
	}
}

// probeServer asks the server at listen for the zone's SOA over UDP; an
// empty host means localhost. Without a zone, any well-formed DNS reply
// (the root query is REFUSED) shows the server is answering.
func probeServer(listen, zone string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeSOA)
	resp, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(m, net.JoinHostPort(host, port))
	if err != nil {
		return err
	}
	if zone == "" {
		return nil
	}
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		return fmt.Errorf("SOA query for %s: %s with %d answers", zone, dns.RcodeToString[resp.Rcode], len(resp.Answer))
	}
	return nil
}
