package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/sneakybugmaster/transporter/internal/agent"
)

// defaultStateDir is where the agent keeps its key and state.
func defaultStateDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/Library/Application Support/Transporter"
	case "windows":
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Transporter")
		}
		return `C:\ProgramData\Transporter`
	default:
		return "/var/lib/transporter"
	}
}

// upConfig is the parsed form of the `up` flags.
type upConfig struct {
	opts     agent.Options
	logLevel string
}

// parseUp parses the flags shared by `up` and `service install`.
func parseUp(name string, args []string, stderr io.Writer) (upConfig, error) {
	fs, stateDir := newFlagSet(name, stderr)
	coordinator := fs.String("coordinator", os.Getenv("TRANSPORTER_COORDINATOR"), "coordinator URL, e.g. https://mesh.example.com (env TRANSPORTER_COORDINATOR)")
	authKey := fs.String("authkey", os.Getenv("TRANSPORTER_AUTHKEY"), "pre-auth key for enrolling this node (env TRANSPORTER_AUTHKEY)")
	hostname := fs.String("hostname", os.Getenv("TRANSPORTER_HOSTNAME"), "name to register with (default: system hostname) (env TRANSPORTER_HOSTNAME)")
	port := fs.Uint("listen-port", 41641, "UDP port for WireGuard")
	iface := fs.String("interface", "transporter0", "name of the TUN interface (ignored on macOS, which picks utunN)")
	advertise := fs.String("advertise-endpoints", os.Getenv("TRANSPORTER_ADVERTISE_ENDPOINTS"), "comma-separated extra ip:port endpoints peers can reach this node on, e.g. a port-forward (env TRANSPORTER_ADVERTISE_ENDPOINTS)")
	logLevel := fs.String("log-level", envOr("TRANSPORTER_LOG_LEVEL", "info"), "log level: debug, info, warn, error (env TRANSPORTER_LOG_LEVEL)")
	userspace := fs.Bool("userspace", envBool("TRANSPORTER_USERSPACE"), "use an in-process network stack instead of a TUN interface: no root needed; programs reach the mesh through the SOCKS5 proxy (env TRANSPORTER_USERSPACE)")
	socks := fs.String("socks5", os.Getenv("TRANSPORTER_SOCKS5"), `SOCKS5 proxy listen address; defaults to 127.0.0.1:1055 with --userspace, "off" disables (env TRANSPORTER_SOCKS5)`)
	if err := fs.Parse(args); err != nil {
		return upConfig{}, err
	}
	switch {
	case *socks == "off":
		*socks = ""
	case *socks == "" && *userspace:
		*socks = "127.0.0.1:1055"
	}
	if *coordinator == "" {
		return upConfig{}, errors.New("--coordinator is required")
	}
	if *port == 0 || *port > 65535 {
		return upConfig{}, fmt.Errorf("invalid --listen-port %d", *port)
	}
	var endpoints []netip.AddrPort
	for s := range strings.SplitSeq(*advertise, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		ep, err := netip.ParseAddrPort(s)
		if err != nil {
			return upConfig{}, fmt.Errorf("invalid advertised endpoint %q: %w", s, err)
		}
		endpoints = append(endpoints, ep)
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return upConfig{}, fmt.Errorf("invalid log level %q", *logLevel)
	}
	dir, err := filepath.Abs(*stateDir)
	if err != nil {
		return upConfig{}, err
	}
	return upConfig{
		logLevel: *logLevel,
		opts: agent.Options{
			CoordinatorURL:     strings.TrimRight(*coordinator, "/"),
			AuthKey:            *authKey,
			Hostname:           *hostname,
			StateDir:           dir,
			ListenPort:         uint16(*port),
			Interface:          *iface,
			AdvertiseEndpoints: endpoints,
			Userspace:          *userspace,
			SOCKS5:             *socks,
		},
	}, nil
}

// serviceArgs renders the configuration as an explicit `up` command line
// for a service: environment variables are not inherited there, and the
// auth key is left out (the node is enrolled before installing).
func (c upConfig) serviceArgs() []string {
	o := c.opts
	args := []string{
		"up",
		"--coordinator", o.CoordinatorURL,
		"--state-dir", o.StateDir,
		"--listen-port", strconv.Itoa(int(o.ListenPort)),
		"--interface", o.Interface,
		"--log-level", c.logLevel,
	}
	if o.Hostname != "" {
		args = append(args, "--hostname", o.Hostname)
	}
	if len(o.AdvertiseEndpoints) > 0 {
		eps := make([]string, len(o.AdvertiseEndpoints))
		for i, ep := range o.AdvertiseEndpoints {
			eps[i] = ep.String()
		}
		args = append(args, "--advertise-endpoints", strings.Join(eps, ","))
	}
	if o.Userspace {
		args = append(args, "--userspace")
	}
	socks := o.SOCKS5
	if socks == "" {
		socks = "off"
	}
	return append(args, "--socks5", socks)
}

func cmdUp(ctx context.Context, args []string, stderr io.Writer) error {
	cfg, err := parseUp("up", args, stderr)
	if err != nil {
		return err
	}
	var level slog.Level
	_ = level.UnmarshalText([]byte(cfg.logLevel))
	cfg.opts.Log = slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))
	return agent.Run(ctx, cfg.opts)
}
