// Command transporter-coordinator runs the public coordination server and
// offers administrative subcommands that operate on its database.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/sneakybugmaster/transporter/internal/coordinator"
	"github.com/sneakybugmaster/transporter/internal/coordinator/adminapi"
	"github.com/sneakybugmaster/transporter/internal/coordinator/control"
	"github.com/sneakybugmaster/transporter/internal/coordinator/datalock"
	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
	"github.com/sneakybugmaster/transporter/internal/metrics"
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
  transporter-coordinator backup <file>         Copy the database (safe while running)
  transporter-coordinator restore <file>        Replace the database (coordinator stopped)

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
		case "backup", "restore":
			return backupCmd(args[0], args[1:], stdout)
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
	tlsDomains := fs.String("tls-domains", os.Getenv("TRANSPORTER_TLS_DOMAINS"), "serve HTTPS with Let's Encrypt certificates for these comma-separated names (TLS-ALPN-01 on the TLS port) (env TRANSPORTER_TLS_DOMAINS)")
	acmeEmail := fs.String("acme-email", os.Getenv("TRANSPORTER_ACME_EMAIL"), "contact address for Let's Encrypt (env TRANSPORTER_ACME_EMAIL)")
	tlsCert := fs.String("tls-cert", os.Getenv("TRANSPORTER_TLS_CERT"), "serve HTTPS with this certificate file (PEM; reloaded when it changes) (env TRANSPORTER_TLS_CERT)")
	tlsKey := fs.String("tls-key", os.Getenv("TRANSPORTER_TLS_KEY"), "private key for --tls-cert (env TRANSPORTER_TLS_KEY)")
	tlsListen := fs.String("tls-listen", envOr("TRANSPORTER_TLS_LISTEN", ":443"), "HTTPS listen address when TLS is enabled (env TRANSPORTER_TLS_LISTEN)")
	oidcIssuer := fs.String("oidc-issuer", os.Getenv("TRANSPORTER_OIDC_ISSUER"), "OpenID Connect issuer URL for admin single sign-on, e.g. https://accounts.google.com (env TRANSPORTER_OIDC_ISSUER)")
	oidcClientID := fs.String("oidc-client-id", os.Getenv("TRANSPORTER_OIDC_CLIENT_ID"), "OIDC client ID (env TRANSPORTER_OIDC_CLIENT_ID)")
	oidcAllowed := fs.String("oidc-allowed", os.Getenv("TRANSPORTER_OIDC_ALLOWED"), "comma-separated emails or @domains allowed to sign in as admins (env TRANSPORTER_OIDC_ALLOWED)")
	oidcName := fs.String("oidc-name", envOr("TRANSPORTER_OIDC_NAME", "single sign-on"), "label of the sign-in button (env TRANSPORTER_OIDC_NAME)")
	oidcRedirect := fs.String("oidc-redirect-url", os.Getenv("TRANSPORTER_OIDC_REDIRECT_URL"), "callback URL registered with the provider; default <public URL>/api/v1/auth/oidc/callback (env TRANSPORTER_OIDC_REDIRECT_URL)")
	metricsListen := fs.String("metrics-listen", os.Getenv("TRANSPORTER_METRICS_LISTEN"), "address for Prometheus metrics at /metrics, e.g. 127.0.0.1:9090; empty disables (env TRANSPORTER_METRICS_LISTEN)")
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

	if err := os.MkdirAll(*dataDir, 0o700); err != nil { //nolint:gosec // operator-supplied path
		return fmt.Errorf("create data dir: %w", err)
	}
	lock, err := datalock.Acquire(*dataDir)
	if err != nil {
		return err
	}
	defer lock.Release() //nolint:errcheck // released on exit anyway

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
	var rs *relay.Server
	if *relayOn {
		opts.RelayEnabled = true
		rs = relay.NewServer(func(ctx context.Context, token string) (wgkey.Key, error) {
			n, err := st.NodeByToken(ctx, token)
			if err == nil && n.Expired(time.Now()) {
				err = errors.New("node key expired")
			}
			return n.WGPublicKey, err
		}, *relayRate, 2**relayRate, log.With("component", "relay"))
		server.Mount(relay.Path, rs)
	}
	ctl := control.NewService(st, prefix, opts, log)
	if rs != nil {
		go pruneRelay(ctx, st, ctl, rs, log)
	}
	server.Mount(ctl.Handler())
	apiOpts := adminapi.Options{SetupCode: *setupCode}
	if *oidcIssuer != "" {
		// The secret only comes from the environment, never the command
		// line, where other users could read it.
		secret := os.Getenv("TRANSPORTER_OIDC_CLIENT_SECRET")
		if *oidcClientID == "" || *oidcAllowed == "" {
			return errors.New("single sign-on needs --oidc-client-id and --oidc-allowed (and TRANSPORTER_OIDC_CLIENT_SECRET)")
		}
		apiOpts.OIDC = &adminapi.OIDCConfig{
			Issuer: *oidcIssuer, ClientID: *oidcClientID, ClientSecret: secret, RedirectURL: *oidcRedirect,
			Allowed: strings.Split(*oidcAllowed, ","), Name: *oidcName,
		}
		log.Info("admin single sign-on enabled", "issuer", *oidcIssuer, "allowed", *oidcAllowed)
	}
	admin, err := adminapi.New(ctx, st, ctl, apiOpts, log.With("component", "admin"))
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

	errc := make(chan error, 3)
	tlsConfig, err := tlsSetup(*tlsDomains, *acmeEmail, *tlsCert, *tlsKey, *dataDir)
	if err != nil {
		return err
	}
	if tlsConfig != nil {
		tprotocols := new(http.Protocols)
		tprotocols.SetHTTP1(true)
		tprotocols.SetHTTP2(true)
		tsrv := &http.Server{
			Addr:              *tlsListen,
			Handler:           server.Handler(),
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 10 * time.Second,
			Protocols:         tprotocols,
			BaseContext:       func(net.Listener) context.Context { return baseCtx },
		}
		go func() {
			log.Info("HTTPS listening", "addr", *tlsListen)
			errc <- fmt.Errorf("HTTPS listener: %w", tsrv.ListenAndServeTLS("", ""))
		}()
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = tsrv.Shutdown(sctx)
		}()
	}
	if *metricsListen != "" {
		registerMetrics(ctx, st, ctl, rs)
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", metrics.Handler())
		msrv := &http.Server{Addr: *metricsListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Info("metrics listening", "addr", *metricsListen)
			errc <- fmt.Errorf("metrics listener: %w", msrv.ListenAndServe())
		}()
		defer msrv.Close()
	}
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

// tlsSetup returns the TLS configuration for HTTPS: Let's Encrypt
// certificates for domains, or a certificate file reloaded when it changes.
// It returns nil when HTTPS is not configured.
func tlsSetup(domains, email, certFile, keyFile, dataDir string) (*tls.Config, error) {
	switch {
	case domains != "" && certFile != "":
		return nil, errors.New("use either --tls-domains or --tls-cert, not both")
	case domains != "":
		var names []string
		for d := range strings.SplitSeq(domains, ",") {
			if d = strings.TrimSpace(d); d != "" {
				names = append(names, d)
			}
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(names...),
			Cache:      autocert.DirCache(filepath.Join(dataDir, "acme")),
			Email:      email,
		}
		cfg := m.TLSConfig()
		cfg.MinVersion = tls.VersionTLS12
		return cfg, nil
	case certFile != "":
		if keyFile == "" {
			return nil, errors.New("--tls-cert needs --tls-key")
		}
		r := &certReloader{cert: certFile, key: keyFile}
		if _, err := r.get(nil); err != nil {
			return nil, err
		}
		return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.get, NextProtos: []string{"h2", "http/1.1"}}, nil
	}
	return nil, nil //nolint:nilnil // nil config means plain HTTP only
}

// certReloader serves a certificate from files, reloading them when the
// certificate file changes (e.g. after renewal by another tool).
type certReloader struct {
	cert, key string
	mu        sync.Mutex
	loaded    *tls.Certificate
	mtime     time.Time
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	fi, err := os.Stat(r.cert)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loaded != nil && fi.ModTime().Equal(r.mtime) {
		return r.loaded, nil
	}
	c, err := tls.LoadX509KeyPair(r.cert, r.key)
	if err != nil {
		if r.loaded != nil {
			return r.loaded, nil // keep serving the old one while files are being replaced
		}
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	r.loaded, r.mtime = &c, fi.ModTime()
	return r.loaded, nil
}

// backupCmd copies the database out (backup) or puts a copy back (restore).
func backupCmd(op string, args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet(op, flag.ContinueOnError)
	dataDir := dataDirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: %s <file>", op)
	}
	file := fs.Arg(0)
	ctx := context.Background()
	if op == "backup" {
		st, err := openStore(ctx, *dataDir)
		if err != nil {
			return err
		}
		defer st.Close()
		if err := st.Backup(ctx, file); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		fmt.Fprintf(stdout, "database copied to %s\n", file)
		return nil
	}

	// Restore: the coordinator must be stopped, and the backup must be a
	// healthy database before anything is touched.
	lock, err := datalock.Acquire(*dataDir)
	if err != nil {
		return fmt.Errorf("%w: stop it before restoring", err)
	}
	defer lock.Release() //nolint:errcheck // released on exit anyway
	tmp := filepath.Join(*dataDir, store.DBFile+".restoring")
	_ = os.Remove(tmp) //nolint:gosec // operator-supplied data dir
	if err := copyFile(file, tmp); err != nil {
		return err
	}
	bk, err := store.OpenFile(ctx, tmp) // also migrates an older backup
	if err != nil {
		_ = os.Remove(tmp) //nolint:gosec // see above
		return fmt.Errorf("%s is not a usable backup: %w", file, err)
	}
	err = bk.Check(ctx)
	_ = bk.Close()
	if err != nil {
		_ = os.Remove(tmp) //nolint:gosec // see above
		return fmt.Errorf("%s is damaged: %w", file, err)
	}
	db := filepath.Join(*dataDir, store.DBFile)
	if _, err := os.Stat(db); err == nil { //nolint:gosec // operator-supplied data dir
		old := db + ".before-restore-" + time.Now().Format("20060102-150405")
		if err := os.Rename(db, old); err != nil { //nolint:gosec // operator-supplied data dir
			return err
		}
		fmt.Fprintf(stdout, "previous database kept as %s\n", old)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(db + suffix) //nolint:gosec // the old database's files
	}
	if err := os.Rename(tmp, db); err != nil { //nolint:gosec // operator-supplied data dir
		return err
	}
	fmt.Fprintf(stdout, "restored %s; start the coordinator\n", file)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // operator-supplied path
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // inside the data dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// registerMetrics adds metrics read at scrape time.
func registerMetrics(ctx context.Context, st *store.Store, ctl *control.Service, rs *relay.Server) {
	countNodes := func(online bool) float64 {
		nodes, err := st.ListNodes(ctx)
		if err != nil {
			return math.NaN()
		}
		n := 0
		for _, nd := range nodes {
			if ctl.Online(nd.ID) == online {
				n++
			}
		}
		return float64(n)
	}
	metrics.Gauge("transporter_nodes_online", "Nodes with an open netmap stream.", func() float64 { return countNodes(true) })
	metrics.Gauge("transporter_nodes_offline", "Enrolled nodes without a netmap stream.", func() float64 { return countNodes(false) })
	metrics.Counter("transporter_stun_requests_total", "STUN binding requests answered.", func() float64 { return float64(stun.Requests()) })
	if rs == nil {
		return
	}
	stats := rs.Stats()
	metrics.Gauge("transporter_relay_connections", "Nodes connected to the relay.", func() float64 { return float64(rs.Connections()) })
	metrics.Counter("transporter_relay_bytes_total", "Payload bytes forwarded by the relay.", func() float64 { return float64(stats.Bytes.Load()) })
	metrics.Counter("transporter_relay_dropped_rate_limit_total", "Relay packets dropped by the per-node rate limit.", func() float64 { return float64(stats.DroppedRateLimit.Load()) })
	metrics.Counter("transporter_relay_dropped_no_peer_total", "Relay packets for nodes not connected to the relay.", func() float64 { return float64(stats.DroppedNoPeer.Load()) })
	metrics.Counter("transporter_relay_dropped_slow_peer_total", "Relay packets dropped because the receiver fell behind.", func() float64 { return float64(stats.DroppedSlowPeer.Load()) })
}

// pruneRelay closes relay connections of deleted nodes whenever the mesh
// changes, and periodically for deletions made with the CLI.
func pruneRelay(ctx context.Context, st *store.Store, ctl *control.Service, rs *relay.Server, log *slog.Logger) {
	events, stop := ctl.Subscribe()
	defer stop()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-events:
		case <-t.C:
		}
		nodes, err := st.ListNodes(ctx)
		if err != nil {
			log.Warn("relay prune", "err", err)
			continue
		}
		keys := make(map[wgkey.Key]bool, len(nodes))
		for _, n := range nodes {
			keys[n.WGPublicKey] = true
		}
		rs.Prune(func(k wgkey.Key) bool { return keys[k] })
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
