// Command transporter-coordinator runs the public coordination server and
// offers administrative subcommands that operate on its database.
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
	"slices"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/sneakybugmaster/transporter/internal/coordinator"
	"github.com/sneakybugmaster/transporter/internal/coordinator/adminapi"
	"github.com/sneakybugmaster/transporter/internal/coordinator/control"
	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
	"github.com/sneakybugmaster/transporter/internal/policy"
	"github.com/sneakybugmaster/transporter/internal/relay"
	"github.com/sneakybugmaster/transporter/internal/stun"
	"github.com/sneakybugmaster/transporter/internal/version"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
	"github.com/sneakybugmaster/transporter/web"
)

const usage = `Transporter coordinator

Usage:
  transporter-coordinator [serve] [flags]     Run the server (default)
  transporter-coordinator authkey create [--reusable] [--ttl 24h] [--description text]
  transporter-coordinator authkey list
  transporter-coordinator authkey revoke <id>
  transporter-coordinator nodes list
  transporter-coordinator nodes delete <name>
  transporter-coordinator nodes tag <name> [tag:x ...]
  transporter-coordinator nodes approve-routes <name> [cidr ...]
  transporter-coordinator policy get
  transporter-coordinator policy set <file|->

Changes made with these commands reach nodes within 30 seconds.

Admin subcommands accept --data-dir (env TRANSPORTER_DATA_DIR) and may be run
while the server is running.

Server flags:
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return serve(args[1:])
		case "authkey":
			return authkeyCmd(args[1:], stdout)
		case "nodes":
			return nodesCmd(args[1:], stdout)
		case "policy":
			return policyCmd(args[1:], os.Stdin, stdout)
		}
	}
	return serve(args)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("transporter-coordinator", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	listen := fs.String("listen", envOr("TRANSPORTER_LISTEN", ":8080"), "HTTP listen address (env TRANSPORTER_LISTEN)")
	dataDir := dataDirFlag(fs)
	logLevel := fs.String("log-level", envOr("TRANSPORTER_LOG_LEVEL", "info"), "log level: debug, info, warn, error (env TRANSPORTER_LOG_LEVEL)")
	prefixStr := fs.String("network-prefix", envOr("TRANSPORTER_NETWORK_PREFIX", "100.64.0.0/10"), "overlay IPv4 network nodes get addresses from (env TRANSPORTER_NETWORK_PREFIX)")
	stunListen := fs.String("stun-listen", envOr("TRANSPORTER_STUN_LISTEN", ":3478"), "UDP address for the STUN server nodes use to learn their public address; empty disables (env TRANSPORTER_STUN_LISTEN)")
	relayOn := fs.Bool("relay", envOr("TRANSPORTER_RELAY", "true") == "true", "relay packets between nodes that cannot connect directly (env TRANSPORTER_RELAY)")
	relayRate := fs.Int("relay-rate", envInt("TRANSPORTER_RELAY_RATE", 4<<20), "relay bandwidth per node in bytes/s, 0 for unlimited (env TRANSPORTER_RELAY_RATE)")
	setupCode := fs.String("setup-code", os.Getenv("TRANSPORTER_SETUP_CODE"), "one-time code for the first-run setup wizard; random and logged if unset (env TRANSPORTER_SETUP_CODE)")
	bootstrapKey := fs.String("bootstrap-authkey", os.Getenv("TRANSPORTER_BOOTSTRAP_AUTHKEY"), "ensure a reusable auth key with this value exists, for automated setups (env TRANSPORTER_BOOTSTRAP_AUTHKEY)")
	showVersion := fs.Bool("version", false, "print version and exit")
	healthcheck := fs.Bool("healthcheck", false, "probe /healthz on the listen address and exit 0 if healthy (for container health checks)")
	if err := fs.Parse(args); err != nil {
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

	prefix, err := netip.ParsePrefix(*prefixStr)
	if err != nil || !prefix.Addr().Is4() {
		return fmt.Errorf("invalid network prefix %q: must be an IPv4 CIDR", *prefixStr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := openStore(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	if *bootstrapKey != "" {
		if _, err := st.EnsureAuthKey(ctx, *bootstrapKey, store.AuthKeyOptions{Reusable: true, Description: "bootstrap"}); err != nil {
			return fmt.Errorf("bootstrap auth key: %w", err)
		}
	}

	var opts control.Options
	if *stunListen != "" {
		pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", *stunListen)
		if err != nil {
			return fmt.Errorf("STUN listener: %w", err)
		}
		opts.STUNPort = uint16(pc.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // ports fit in uint16
		go func() {
			if err := stun.Serve(ctx, pc, log); err != nil {
				log.Error("STUN server", "err", err)
			}
		}()
		log.Info("STUN server listening", "addr", pc.LocalAddr())
	}

	server := coordinator.NewServer(log, web.FS())
	if *relayOn {
		opts.RelayEnabled = true
		rs := relay.NewServer(func(ctx context.Context, token string) (wgkey.Key, error) {
			n, err := st.NodeByToken(ctx, token)
			return n.WGPublicKey, err
		}, *relayRate, 2**relayRate, log.With("component", "relay"))
		server.Mount(relay.Path, rs)
	}
	ctl := control.NewService(st, prefix, opts, log)
	server.Mount(ctl.Handler())
	admin, err := adminapi.New(ctx, st, ctl, *setupCode, log.With("component", "admin"))
	if err != nil {
		return err
	}
	server.Mount(adminapi.BasePath+"/", admin.Handler())

	// Request contexts derive from baseCtx; cancelling it on shutdown ends
	// long-lived control streams so Shutdown does not wait for them.
	baseCtx, cancelBase := context.WithCancel(context.Background())
	defer cancelBase()

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true) // lets gRPC clients connect without TLS
	srv := &http.Server{
		Addr:              *listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		Protocols:         protocols,
		BaseContext:       func(net.Listener) context.Context { return baseCtx },
	}

	errc := make(chan error, 1)
	go func() {
		log.Info("coordinator starting", "listen", *listen, "dataDir", *dataDir, "networkPrefix", prefix, "version", version.Version)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	log.Info("shutting down")
	cancelBase()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func authkeyCmd(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: authkey create|list|revoke")
	}
	fs := flag.NewFlagSet("authkey "+args[0], flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	reusable := fs.Bool("reusable", false, "allow the key to enroll more than one node")
	ttl := fs.Duration("ttl", 24*time.Hour, "key lifetime; 0 for no expiry")
	desc := fs.String("description", "", "free-text description")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := openStore(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "create":
		k, secret, err := st.CreateAuthKey(ctx, store.AuthKeyOptions{Description: *desc, Reusable: *reusable, TTL: *ttl})
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s\n", secret)
		fmt.Fprintf(os.Stderr, "created auth key %s (reusable=%t, expires=%s); the secret above is shown only once\n",
			k.ID, k.Reusable, fmtTime(k.ExpiresAt))
		return nil
	case "list":
		keys, err := st.ListAuthKeys(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tDESCRIPTION\tREUSABLE\tUSED\tSTATE\tEXPIRES")
		now := time.Now()
		for _, k := range keys {
			state := "valid"
			switch {
			case k.Revoked:
				state = "revoked"
			case !k.Valid(now):
				state = "expired/used"
			}
			fmt.Fprintf(tw, "%s\t%s\t%t\t%d\t%s\t%s\n", k.ID, k.Description, k.Reusable, k.UsedCount, state, fmtTime(k.ExpiresAt))
		}
		return tw.Flush()
	case "revoke":
		if fs.NArg() != 1 {
			return errors.New("usage: authkey revoke <id>")
		}
		return st.RevokeAuthKey(ctx, fs.Arg(0))
	default:
		return fmt.Errorf("unknown authkey command %q", args[0])
	}
}

func nodesCmd(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: nodes list|delete|tag|approve-routes")
	}
	fs := flag.NewFlagSet("nodes "+args[0], flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := openStore(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "list":
		nodes, err := st.ListNodes(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tADDRESS\tOS\tLAST SEEN\tTAGS\tROUTES\tENDPOINTS")
		for _, n := range nodes {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%v\n", n.Name, n.IPv4, n.OS, n.LastSeen.Local().Format(time.DateTime),
				dash(strings.Join(n.Tags, ",")), dash(routesSummary(n)), n.Endpoints)
		}
		return tw.Flush()
	case "delete":
		if fs.NArg() != 1 {
			return errors.New("usage: nodes delete <name>")
		}
		n, err := st.NodeByName(ctx, fs.Arg(0))
		if err != nil {
			return fmt.Errorf("node %q: %w", fs.Arg(0), err)
		}
		if err := st.DeleteNode(ctx, n.ID); err != nil {
			return err
		}
		return st.AppendAudit(ctx, store.AuditEntry{Actor: "cli", Action: "node.delete", Target: n.Name})
	case "tag", "approve-routes":
		if fs.NArg() < 1 {
			return fmt.Errorf("usage: nodes %s <name> [values...]", args[0])
		}
		n, err := st.NodeByName(ctx, fs.Arg(0))
		if err != nil {
			return fmt.Errorf("node %q: %w", fs.Arg(0), err)
		}
		if args[0] == "tag" {
			tags := []string{}
			for _, t := range fs.Args()[1:] {
				if !policy.ValidTag(t) {
					return fmt.Errorf("invalid tag %q: want tag:<name>", t)
				}
				tags = append(tags, t)
			}
			if _, err := st.SetNodeTags(ctx, n.ID, tags); err != nil {
				return err
			}
			return st.AppendAudit(ctx, store.AuditEntry{Actor: "cli", Action: "node.tags", Target: n.Name, Detail: strings.Join(tags, ", ")})
		}
		routes := []netip.Prefix{}
		for _, r := range fs.Args()[1:] {
			p, err := netip.ParsePrefix(r)
			if err != nil || !p.Addr().Is4() {
				return fmt.Errorf("invalid route %q", r)
			}
			routes = append(routes, p.Masked())
		}
		if _, err := st.SetApprovedRoutes(ctx, n.ID, routes); err != nil {
			return err
		}
		return st.AppendAudit(ctx, store.AuditEntry{Actor: "cli", Action: "node.routes", Target: n.Name, Detail: "approved: " + strings.Join(fs.Args()[1:], ", ")})
	default:
		return fmt.Errorf("unknown nodes command %q", args[0])
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// routesSummary shows routes in use, and advertised ones awaiting approval
// with a trailing "?".
func routesSummary(n store.Node) string {
	var parts []string
	for _, r := range n.AdvertisedRoutes {
		if slices.Contains(n.ApprovedRoutes, r) {
			parts = append(parts, r.String())
		} else {
			parts = append(parts, r.String()+"?")
		}
	}
	return strings.Join(parts, ",")
}

// policyCmd reads or replaces the access-control policy.
func policyCmd(args []string, stdin io.Reader, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: policy get|set <file|->")
	}
	fs := flag.NewFlagSet("policy "+args[0], flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx := context.Background()
	st, err := openStore(ctx, *dataDir)
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "get":
		text, err := st.Setting(ctx, store.SettingPolicy)
		if err != nil {
			return err
		}
		if text == "" {
			text = policy.Default
		}
		_, err = io.WriteString(stdout, text)
		return err
	case "set":
		if fs.NArg() != 1 {
			return errors.New("usage: policy set <file|->")
		}
		var b []byte
		if fs.Arg(0) == "-" {
			b, err = io.ReadAll(io.LimitReader(stdin, 1<<20))
		} else {
			b, err = os.ReadFile(fs.Arg(0)) //nolint:gosec // operator-supplied path
		}
		if err != nil {
			return err
		}
		p, err := policy.Parse(b)
		if err != nil {
			return err
		}
		nodes, err := st.ListNodes(ctx)
		if err != nil {
			return err
		}
		pn := make([]policy.Node, len(nodes))
		for i, n := range nodes {
			pn[i] = policy.Node{Name: n.Name, IP: n.IPv4, Tags: n.Tags, Routes: n.Routes()}
		}
		if errs := p.RunTests(pn); len(errs) > 0 {
			return fmt.Errorf("policy tests failed: %w", errors.Join(errs...))
		}
		if err := st.SetSetting(ctx, store.SettingPolicy, string(b)); err != nil {
			return err
		}
		if err := st.AppendAudit(ctx, store.AuditEntry{Actor: "cli", Action: "policy.update"}); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "policy saved; nodes pick it up within 30 seconds")
		return nil
	default:
		return fmt.Errorf("unknown policy command %q", args[0])
	}
}

func dataDirFlag(fs *flag.FlagSet) *string {
	return fs.String("data-dir", envOr("TRANSPORTER_DATA_DIR", "./data"), "directory for persistent state (env TRANSPORTER_DATA_DIR)")
}

func openStore(ctx context.Context, dataDir string) (*store.Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil { //nolint:gosec // operator-supplied path
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(ctx, dataDir)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return st, nil
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.Local().Format(time.DateTime)
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

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
