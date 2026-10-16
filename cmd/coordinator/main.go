// Command transporter-coordinator runs the public coordination server.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sneakybugmaster/transporter/internal/coordinator"
	"github.com/sneakybugmaster/transporter/internal/version"
	"github.com/sneakybugmaster/transporter/web"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("transporter-coordinator", flag.ContinueOnError)
	listen := fs.String("listen", envOr("TRANSPORTER_LISTEN", ":8080"), "HTTP listen address (env TRANSPORTER_LISTEN)")
	dataDir := fs.String("data-dir", envOr("TRANSPORTER_DATA_DIR", "./data"), "directory for persistent state (env TRANSPORTER_DATA_DIR)")
	logLevel := fs.String("log-level", envOr("TRANSPORTER_LOG_LEVEL", "info"), "log level: debug, info, warn, error (env TRANSPORTER_LOG_LEVEL)")
	showVersion := fs.Bool("version", false, "print version and exit")
	healthcheck := fs.Bool("healthcheck", false, "probe /healthz on the listen address and exit 0 if healthy (for container health checks)")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Println("transporter-coordinator", version.String())
		return nil
	}
	if *healthcheck {
		return probe(*listen)
	}

	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("invalid log level %q", *logLevel)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           coordinator.NewServer(log, web.FS()).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Info("coordinator starting", "listen", *listen, "dataDir", *dataDir, "version", version.Version)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// probe checks the health endpoint of a coordinator listening on addr.
func probe(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/healthz", http.NoBody)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	return nil
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
