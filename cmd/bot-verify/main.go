// Command bot-verify collects bot operators' published IP lists, checks
// reverse DNS live, and answers "is this IP really this bot?" over HTTP.
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
	"os"
	"os/signal"
	"syscall"
	"time"

	"bot-verify/internal/api"
	"bot-verify/internal/catalog"
	"bot-verify/internal/rdns"
	"bot-verify/internal/sources"
	"bot-verify/internal/store"
	"bot-verify/internal/verify"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

// newFetchClient builds the client for operator sources; tests replace it.
var newFetchClient = func() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "bot-verify:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("bot-verify", flag.ContinueOnError)
	listen := flags.String("listen", ":8080", "HTTP listen address")
	botsPath := flags.String("bots", "bots.yaml", "bot catalog file")
	refresh := flags.Duration("refresh", 6*time.Hour, "interval between source refreshes")
	rdnsTTL := flags.Duration("rdns-ttl", 15*time.Minute, "cache lifetime of reverse-DNS answers")
	rdnsConcurrency := flags.Int("rdns-concurrency", 64, "maximum concurrent reverse-DNS checks")
	showVersion := flags.Bool("version", false, "print version and exit")
	probe := flags.Bool("probe", false, "check /healthz of the server at -listen and exit (container health check)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintln(stdout, "bot-verify", version)
		return nil
	}
	if *probe {
		return probeHealth(*listen)
	}
	if *refresh <= 0 || *rdnsTTL <= 0 || *rdnsConcurrency <= 0 {
		return errors.New("-refresh, -rdns-ttl and -rdns-concurrency must be positive")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	sources.UserAgent = "bot-verify/" + version + " (+https://goodbot-badbot.com)"

	cat, err := catalog.Load(*botsPath, sources.KnownFormat)
	if err != nil {
		return err
	}
	st := store.New()
	client := newFetchClient()
	go store.RunScheduler(ctx, *refresh, func(ctx context.Context) {
		errs := store.Refresh(ctx, cat, client, st, time.Now)
		for _, err := range errs {
			logger.Warn("source refresh failed", "error", err.Error())
		}
		logger.Info("sources refreshed", "failed", len(errs))
	})

	checker := rdns.NewChecker(net.DefaultResolver, *rdnsTTL, *rdnsConcurrency, time.Now)
	verifier := verify.New(cat, st, checker, time.Now)
	server := &http.Server{
		Handler:           api.NewHandler(verifier, cat, st, logger),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "listening on %s\n", listener.Addr())

	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

// probeHealth GETs /healthz on the listen address; an empty host means localhost.
func probeHealth(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz status %d", resp.StatusCode)
	}
	return nil
}
