// Package agent runs a mesh node: it enrolls with the coordinator, keeps the
// WireGuard engine in sync with the netmap and serves the local API.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/sneakybugmaster/transporter/internal/agent/controlclient"
	"github.com/sneakybugmaster/transporter/internal/agent/engine"
	"github.com/sneakybugmaster/transporter/internal/agent/localapi"
	"github.com/sneakybugmaster/transporter/internal/agent/magicdns"
	"github.com/sneakybugmaster/transporter/internal/agent/magicsock"
	"github.com/sneakybugmaster/transporter/internal/agent/netcfg"
	"github.com/sneakybugmaster/transporter/internal/agent/pingsvc"
	"github.com/sneakybugmaster/transporter/internal/agent/socks5"
	"github.com/sneakybugmaster/transporter/internal/agent/state"
	"github.com/sneakybugmaster/transporter/internal/agent/tundev"
	"github.com/sneakybugmaster/transporter/internal/filter"
	"github.com/sneakybugmaster/transporter/internal/netns"
	controlv1 "github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

// Options configures the agent.
type Options struct {
	CoordinatorURL string
	// AuthKey enrolls the node if it is not registered yet (or its token was
	// revoked). It may be empty for an already-registered node.
	AuthKey            string
	Hostname           string
	StateDir           string
	ListenPort         uint16
	Interface          string
	AdvertiseEndpoints []netip.AddrPort
	// Userspace runs WireGuard over an in-process network stack instead of
	// a kernel TUN interface: no root or NET_ADMIN needed, but programs reach
	// the mesh only through the SOCKS5 proxy.
	Userspace bool
	// SOCKS5 is the listen address of the SOCKS5 proxy into the mesh;
	// empty disables it.
	SOCKS5 string
	// AdvertiseRoutes are subnets this node offers to forward to; with
	// AdvertiseExitNode it also offers to forward to the internet. Both need
	// approval (by an admin or the policy) and TUN mode on Linux.
	AdvertiseRoutes   []netip.Prefix
	AdvertiseExitNode bool
	// AcceptRoutes installs other nodes' approved subnet routes.
	AcceptRoutes bool
	// ExitNode names a peer (by name or mesh IP) to send internet traffic
	// through.
	ExitNode string
	// AcceptDNS points the OS resolver at MagicDNS for mesh names and split
	// DNS domains (TUN mode).
	AcceptDNS bool
	Log       *slog.Logger
}

// advertised returns the routes to advertise, including the exit route.
func (o Options) advertised() []string {
	var out []string
	for _, r := range o.AdvertiseRoutes {
		out = append(out, r.Masked().String())
	}
	if o.AdvertiseExitNode {
		out = append(out, "0.0.0.0/0")
	}
	return out
}

const (
	minBackoff = time.Second
	maxBackoff = 30 * time.Second
)

type agent struct {
	opts   Options
	log    *slog.Logger
	client *controlclient.Client
	eng    *engine.Engine
	conn   *magicsock.Conn
	net    meshNetwork
	iface  *netcfg.Interface // nil in userspace mode
	filter *filter.Filter
	dns    *magicdns.Resolver
	cancel context.CancelFunc
	// updateMu serialises endpoint updates so the latest one wins.
	updateMu sync.Mutex

	mu         sync.Mutex
	st         *state.State
	selfAddr   netip.Addr
	stopPing   context.CancelFunc
	lastErr    string
	runCtx     context.Context
	registered bool // registered during this run
	relayToken string
	stunPort   uint32
	prefix     netip.Prefix
	peers      map[string]netip.Addr // peer name -> mesh address
	routes     []netip.Prefix        // routes this node sends into the mesh
	osDNS      []string              // domains the OS resolver was pointed at
	forwarding bool
	forwardErr string // last forwarding problem logged
	exitState  string // last exit node problem logged
}

// Run runs the agent until ctx is cancelled or it is told to shut down.
func Run(ctx context.Context, opts Options) error {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Hostname == "" {
		opts.Hostname, _ = os.Hostname()
	}
	st, err := state.Load(opts.StateDir)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	client, err := controlclient.New(opts.CoordinatorURL)
	if err != nil {
		return err
	}

	if opts.Userspace && len(opts.advertised()) > 0 {
		return errors.New("advertising routes or an exit node needs TUN mode (not --userspace) on Linux")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a := &agent{opts: opts, log: opts.Log, client: client, st: st, cancel: cancel, runCtx: ctx, filter: filter.New()}
	a.filter.PingPort = pingsvc.Port
	a.dns = &magicdns.Resolver{Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return a.net.DialContext(ctx, network, address)
	}}

	if !st.Registered(opts.CoordinatorURL) {
		if err := a.registerWithRetry(ctx); err != nil {
			return err
		}
	}

	tunDev, netCfg, ifName, err := a.setupInterface(ctx)
	if err != nil {
		return err
	}
	if a.iface != nil {
		defer a.iface.Cleanup() // after the engine (deferred later) closes the interface
	}
	var exclude []string
	if ifName != "" {
		exclude = []string{ifName}
	}
	a.conn = magicsock.New(magicsock.Options{
		PrivateKey:        st.PrivateKey,
		Log:               opts.Log,
		ExcludeInterfaces: exclude,
		ExtraEndpoints:    opts.AdvertiseEndpoints,
		OnEndpoints:       a.onEndpoints,
	})
	defer a.conn.Shutdown()
	a.eng, err = engine.New(engine.Config{
		PrivateKey: st.PrivateKey,
		ListenPort: opts.ListenPort,
		TUN:        tunDev,
		Conn:       a.conn,
		Net:        netCfg,
		Log:        opts.Log,
	})
	if err != nil {
		return err
	}
	defer a.eng.Close()
	mode := "interface " + ifName
	if opts.Userspace {
		mode = "userspace networking"
	}
	a.log.Info("wireguard up", "mode", mode, "listenPort", a.eng.ListenPort(), "publicKey", st.PrivateKey.Public())

	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	wg.Go(func() {
		sock := filepath.Join(opts.StateDir, localapi.SocketName)
		if err := localapi.Serve(ctx, sock, a); err != nil {
			a.log.Error("local API", "err", err)
		}
	})
	if opts.SOCKS5 != "" {
		ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.SOCKS5)
		if err != nil {
			return fmt.Errorf("SOCKS5 listener: %w", err)
		}
		a.log.Info("SOCKS5 proxy listening", "addr", ln.Addr())
		srv := &socks5.Server{Dial: a.dialProxy, Log: a.log.With("component", "socks5")}
		wg.Go(func() {
			if err := srv.Serve(ctx, ln); err != nil {
				a.log.Error("SOCKS5 proxy", "err", err)
			}
		})
	}

	wg.Go(func() { a.reportLoop(ctx) })

	return a.watchLoop(ctx)
}

// reportInterval is how often peer paths are reported for the topology view.
const reportInterval = 30 * time.Second

// reportLoop tells the coordinator how each peer is reached.
func (a *agent) reportLoop(ctx context.Context) {
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		t.Reset(reportInterval)
		st, err := a.eng.Status()
		if err != nil || !st.Connected {
			continue
		}
		var peers []*controlv1.PeerPath
		for _, p := range st.Peers {
			if p.Path != "" {
				peers = append(peers, &controlv1.PeerPath{NodeId: p.ID, Path: p.Path, LatencyMs: p.LatencyMs})
			}
		}
		a.mu.Lock()
		token := a.st.NodeToken
		a.mu.Unlock()
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		if err := a.client.ReportStatus(rctx, token, peers); err != nil {
			a.log.Debug("report status", "err", err)
		}
		cancel()
	}
}

// Enroll registers the node with the coordinator (if it is not already) and
// saves its identity, without bringing the mesh up. Service installation
// uses it so the auth key never has to be stored in service configuration.
func Enroll(ctx context.Context, opts Options) error {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Hostname == "" {
		opts.Hostname, _ = os.Hostname()
	}
	st, err := state.Load(opts.StateDir)
	if err != nil {
		return fmt.Errorf("load state: %w", err)
	}
	if st.Registered(opts.CoordinatorURL) {
		return nil
	}
	client, err := controlclient.New(opts.CoordinatorURL)
	if err != nil {
		return err
	}
	a := &agent{opts: opts, log: opts.Log, client: client, st: st, runCtx: ctx}
	return a.register(ctx)
}

func (a *agent) register(ctx context.Context) error {
	if a.opts.AuthKey == "" {
		return fmt.Errorf("this node is not registered with %s: pass an auth key (--authkey)", a.opts.CoordinatorURL)
	}
	resp, err := a.client.Register(ctx, &controlv1.RegisterRequest{
		AuthKey:            a.opts.AuthKey,
		WireguardPublicKey: a.publicKey().Bytes(),
		Hostname:           a.opts.Hostname,
		Os:                 runtime.GOOS,
	})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	a.mu.Lock()
	a.st.CoordinatorURL = a.opts.CoordinatorURL
	a.st.NodeID = resp.GetNode().GetId()
	a.st.NodeToken = resp.GetNodeToken()
	a.st.Name = resp.GetNode().GetName()
	if addrs := resp.GetNode().GetAddresses(); len(addrs) > 0 {
		a.st.Address = addrs[0]
	}
	a.registered = true
	err = a.st.Save(a.opts.StateDir)
	a.mu.Unlock()
	if err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	a.log.Info("registered", "name", resp.GetNode().GetName(), "addresses", resp.GetNode().GetAddresses())
	return nil
}

// registerWithRetry registers, retrying while the coordinator is unreachable.
// A rejected auth key is final.
func (a *agent) registerWithRetry(ctx context.Context) error {
	backoff := minBackoff
	for {
		err := a.register(ctx)
		if err == nil || a.opts.AuthKey == "" || errors.Is(err, controlclient.ErrUnauthenticated) {
			return err
		}
		a.log.Warn("registration failed, retrying", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (a *agent) publicKey() wgkey.Key { return a.st.PrivateKey.Public() }

func (a *agent) watchLoop(ctx context.Context) error {
	backoff := minBackoff
	for {
		start := time.Now()
		a.mu.Lock()
		token := a.st.NodeToken
		a.mu.Unlock()

		err := a.client.Watch(ctx, token, &controlv1.WatchNetmapRequest{
			Endpoints:        a.endpoints(),
			AdvertisedRoutes: a.opts.advertised(),
		}, a.applyNetmap)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, controlclient.ErrUnauthenticated) {
			a.mu.Lock()
			retry := !a.registered && a.opts.AuthKey != ""
			a.mu.Unlock()
			if !retry {
				return fmt.Errorf("coordinator rejected this node (deleted, or its key expired?); run again with --authkey to re-authenticate: %w", err)
			}
			a.log.Warn("node token rejected, re-registering", "err", err)
			if err := a.registerWithRetry(ctx); err != nil {
				return err
			}
			continue
		}

		a.setErr(err)
		if time.Since(start) > maxBackoff {
			backoff = minBackoff
		}
		a.log.Warn("control connection lost, retrying", "err", err, "in", backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

func (a *agent) endpoints() []string {
	var out []string
	for _, ep := range a.conn.Endpoints() {
		out = append(out, ep.String())
	}
	return out
}

// onEndpoints is called by magicsock when this node's reachable addresses
// change (for example its public address, learned via STUN).
func (a *agent) onEndpoints(eps []netip.AddrPort) {
	a.updateMu.Lock()
	defer a.updateMu.Unlock()
	a.mu.Lock()
	token := a.st.NodeToken
	ctx := a.runCtx
	a.mu.Unlock()
	strs := make([]string, 0, len(eps))
	for _, ep := range eps {
		strs = append(strs, ep.String())
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := a.client.UpdateEndpoints(ctx, token, strs); err != nil {
		// The next netmap stream reconnect re-sends the current endpoints.
		a.log.Debug("update endpoints", "err", err)
		return
	}
	a.log.Info("advertising endpoints", "endpoints", strs)
}

// configureNAT points magicsock at the coordinator's STUN server and relay.
func (a *agent) configureNAT(resp *controlv1.WatchNetmapResponse) {
	a.mu.Lock()
	token := a.st.NodeToken
	relayChanged := resp.GetRelayEnabled() && a.relayToken != token
	if relayChanged {
		a.relayToken = token
	}
	stunChanged := resp.GetStunPort() != a.stunPort
	a.stunPort = resp.GetStunPort()
	a.mu.Unlock()

	if relayChanged {
		if err := a.conn.SetRelay(a.opts.CoordinatorURL, token); err != nil {
			a.log.Warn("relay", "err", err)
		}
	}
	if stunChanged && resp.GetStunPort() > 0 && resp.GetStunPort() <= 65535 {
		u, err := url.Parse(a.opts.CoordinatorURL)
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(a.runCtx, 10*time.Second)
		defer cancel()
		ips, err := netns.Resolver().LookupNetIP(ctx, "ip4", u.Hostname())
		if err != nil || len(ips) == 0 {
			a.log.Warn("resolve STUN server", "host", u.Hostname(), "err", err)
			a.mu.Lock()
			a.stunPort = 0 // retry on the next netmap
			a.mu.Unlock()
			return
		}
		addr := netip.AddrPortFrom(ips[0].Unmap(), uint16(resp.GetStunPort())) //nolint:gosec // range checked above
		a.conn.SetSTUNServer(addr)
		a.log.Info("using STUN server", "addr", addr)
	}
}

func (a *agent) applyNetmap(resp *controlv1.WatchNetmapResponse) error {
	nm, err := a.convert(resp)
	if err != nil {
		return err
	}
	a.filter.SetRules(convertFilter(resp.GetPacketFilter()))
	a.dns.SetConfig(dnsConfig(resp.GetDns(), nm))
	if err := a.eng.Apply(nm); err != nil {
		return err
	}
	a.updateState(&nm)
	// OS configuration last: it can take seconds (NRPT on Windows), and the
	// mesh, including the ping service, should work in the meantime.
	a.configureNAT(resp)
	a.configureOS(nm.Prefix)
	return nil
}

// updateState records what the netmap says about this node and its peers.
func (a *agent) updateState(nm *engine.Netmap) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastErr = ""
	a.routes = nm.Routes
	a.registered = false // a fresh token works again; allow re-registering later
	a.prefix = nm.Prefix
	a.peers = make(map[string]netip.Addr, len(nm.Peers))
	for _, p := range nm.Peers {
		if len(p.Addresses) > 0 {
			a.peers[p.Name] = p.Addresses[0].Addr()
		}
	}
	if len(nm.Self.Addresses) > 0 {
		self := nm.Self.Addresses[0]
		if self.String() != a.st.Address {
			a.st.Address = self.String()
			if err := a.st.Save(a.opts.StateDir); err != nil {
				a.log.Warn("save state", "err", err)
			}
		}
		if addr := self.Addr(); addr != a.selfAddr {
			a.selfAddr = addr
			a.startPingLocked(addr)
		}
	}
}

// configureOS points the OS resolver at MagicDNS and, on subnet routers,
// turns on forwarding. Problems are logged, not fatal: the mesh itself
// still works.
func (a *agent) configureOS(prefix netip.Prefix) {
	if a.iface == nil {
		return
	}
	if a.opts.AcceptDNS {
		domains := a.dns.Domains()
		a.mu.Lock()
		changed := !slices.Equal(domains, a.osDNS)
		a.osDNS = domains
		a.mu.Unlock()
		if changed {
			err := a.iface.SetDNS(magicdns.Addr, domains)
			switch {
			case errors.Is(err, netcfg.ErrDNSUnsupported):
				a.log.Info("system DNS not configured; mesh names resolve at "+magicdns.Addr.String(), "reason", err)
			case err != nil:
				a.log.Warn("configure system DNS", "err", err)
			case len(domains) > 0:
				a.log.Info("system DNS configured", "domains", domains, "server", magicdns.Addr)
			}
		}
	}
	a.mu.Lock()
	enable := len(a.opts.advertised()) > 0 && !a.forwarding
	a.mu.Unlock()
	if enable {
		if err := a.iface.EnableForwarding(prefix); err != nil { //nolint:staticcheck // always fails on some OSes
			a.mu.Lock()
			repeated := a.forwardErr == err.Error()
			a.forwardErr = err.Error()
			a.mu.Unlock()
			if !repeated {
				a.log.Warn("subnet routing unavailable", "err", err)
			}
			a.setErr(err)
			return
		}
		a.mu.Lock()
		a.forwarding = true
		a.mu.Unlock()
		a.log.Info("forwarding enabled", "routes", a.opts.advertised())
	}
}

// startPingLocked (re)starts the echo responder on the mesh address.
func (a *agent) startPingLocked(addr netip.Addr) {
	if a.stopPing != nil {
		a.stopPing()
	}
	ctx, cancel := context.WithCancel(a.runCtx)
	a.stopPing = cancel
	go func() {
		pc, err := a.net.ListenUDP(ctx, netip.AddrPortFrom(addr, pingsvc.Port))
		if err != nil {
			a.log.Warn("ping responder", "err", err)
			return
		}
		if err := pingsvc.Serve(ctx, pc); err != nil {
			a.log.Warn("ping responder", "err", err)
		}
	}()
}

func (a *agent) convert(resp *controlv1.WatchNetmapResponse) (engine.Netmap, error) {
	prefix, err := netip.ParsePrefix(resp.GetNetworkPrefix())
	if err != nil {
		return engine.Netmap{}, fmt.Errorf("netmap: bad network prefix %q", resp.GetNetworkPrefix())
	}
	self, err := convertNode(resp.GetSelf())
	if err != nil {
		return engine.Netmap{}, fmt.Errorf("netmap self: %w", err)
	}
	nm := engine.Netmap{Self: self, Prefix: prefix}
	for _, p := range resp.GetPeers() {
		n, err := convertNode(p)
		if err != nil {
			a.log.Warn("skipping malformed peer", "peer", p.GetName(), "err", err)
			continue
		}
		nm.Peers = append(nm.Peers, n)
	}
	slices.SortFunc(nm.Peers, func(x, y engine.Node) int { return strings.Compare(x.Name, y.Name) })
	a.addRoutes(&nm)
	if resp.GetDns().GetMagicDns() && !prefix.Contains(magicdns.Addr) {
		nm.Routes = append(nm.Routes, netip.PrefixFrom(magicdns.Addr, 32))
	}
	return nm, nil
}

// addRoutes gives peers the routes this node uses through them: subnet
// routes with AcceptRoutes, and the default route of the chosen exit node.
// A prefix offered by several peers goes to the first by name.
func (a *agent) addRoutes(nm *engine.Netmap) {
	exitFound, exitOffers := false, false
	used := map[netip.Prefix]bool{}
	for i := range nm.Peers {
		p := &nm.Peers[i]
		isExit := a.opts.ExitNode != "" && (p.Name == a.opts.ExitNode ||
			(len(p.Addresses) > 0 && p.Addresses[0].Addr().String() == a.opts.ExitNode))
		exitFound = exitFound || isExit
		for _, r := range p.Routes {
			if r.Bits() == 0 {
				if !isExit {
					continue
				}
				exitOffers = true
			} else if !a.opts.AcceptRoutes {
				continue
			}
			if used[r] {
				continue
			}
			used[r] = true
			p.Addresses = append(p.Addresses, r)
			nm.Routes = append(nm.Routes, r)
		}
	}
	state := ""
	switch {
	case a.opts.ExitNode == "":
	case !exitFound:
		state = "exit node " + a.opts.ExitNode + " is not in the netmap (unknown, or the policy hides it)"
	case !exitOffers:
		state = "exit node " + a.opts.ExitNode + " does not offer an approved exit route"
	}
	a.mu.Lock()
	changed := state != a.exitState
	a.exitState = state
	a.mu.Unlock()
	if changed && state != "" {
		a.log.Warn(state + "; internet traffic goes out directly")
	} else if changed {
		a.log.Info("using exit node", "node", a.opts.ExitNode)
	}
}

func convertFilter(in []*controlv1.FilterRule) []filter.Rule {
	out := make([]filter.Rule, 0, len(in))
	for _, r := range in {
		var fr filter.Rule
		for _, s := range r.GetSrcPrefixes() {
			if p, err := netip.ParsePrefix(s); err == nil {
				fr.Srcs = append(fr.Srcs, p)
			}
		}
		for _, d := range r.GetDestinations() {
			p, err := netip.ParsePrefix(d.GetPrefix())
			if err != nil || d.GetFirstPort() > 65535 || d.GetLastPort() > 65535 {
				continue
			}
			fr.Dsts = append(fr.Dsts, filter.Dst{Prefix: p, Ports: filter.PortRange{
				First: uint16(d.GetFirstPort()), Last: uint16(d.GetLastPort()), //nolint:gosec // range checked above
			}})
		}
		for _, proto := range r.GetProtocols() {
			if proto <= 255 {
				fr.Protos = append(fr.Protos, uint8(proto))
			}
		}
		if len(r.GetProtocols()) > 0 && len(fr.Protos) == 0 {
			continue // only unknown protocols: matches nothing
		}
		out = append(out, fr)
	}
	return out
}

func dnsConfig(d *controlv1.DnsConfig, nm engine.Netmap) magicdns.Config {
	c := magicdns.Config{Nodes: map[string]netip.Addr{}}
	if d.GetMagicDns() {
		c.Domain = d.GetDomain()
		for _, n := range append([]engine.Node{nm.Self}, nm.Peers...) {
			if len(n.Addresses) > 0 {
				c.Nodes[n.Name] = n.Addresses[0].Addr()
			}
		}
	}
	for _, sd := range d.GetSplitDns() {
		var rs []netip.AddrPort
		for _, r := range sd.GetResolvers() {
			if ap, err := netip.ParseAddrPort(r); err == nil {
				rs = append(rs, ap)
			} else if ip, err := netip.ParseAddr(r); err == nil {
				rs = append(rs, netip.AddrPortFrom(ip, 53))
			}
		}
		if len(rs) > 0 {
			c.Split = append(c.Split, magicdns.Split{Domain: sd.GetDomain(), Resolvers: rs})
		}
	}
	return c
}

func convertNode(p *controlv1.Node) (engine.Node, error) {
	key, err := wgkey.FromBytes(p.GetWireguardPublicKey())
	if err != nil {
		return engine.Node{}, err
	}
	n := engine.Node{ID: p.GetId(), Name: p.GetName(), Key: key, Online: p.GetOnline()}
	for _, s := range p.GetRoutes() {
		if pfx, err := netip.ParsePrefix(s); err == nil && pfx.Addr().Is4() {
			n.Routes = append(n.Routes, pfx.Masked())
		}
	}
	for _, s := range p.GetAddresses() {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return engine.Node{}, fmt.Errorf("address %q: %w", s, err)
		}
		n.Addresses = append(n.Addresses, pfx)
	}
	for _, s := range p.GetEndpoints() {
		if ep, err := netip.ParseAddrPort(s); err == nil {
			n.Endpoints = append(n.Endpoints, ep)
		}
	}
	return n, nil
}

func (a *agent) setErr(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil {
		a.lastErr = err.Error()
	}
}

// Status implements localapi.Backend.
func (a *agent) Status() localapi.Status {
	a.mu.Lock()
	s := localapi.Status{Coordinator: a.st.CoordinatorURL, NodeID: a.st.NodeID, Error: a.lastErr}
	a.mu.Unlock()
	es, err := a.eng.Status()
	if err != nil && s.Error == "" {
		s.Error = err.Error()
	}
	s.Engine = es
	return s
}

// Shutdown implements localapi.Backend.
func (a *agent) Shutdown() {
	a.log.Info("shutdown requested via local API")
	a.cancel()
}

// setupInterface creates the TUN device WireGuard reads and writes: a kernel
// interface, or an in-process network stack in userspace mode.
func (a *agent) setupInterface(ctx context.Context) (tun.Device, engine.NetConfigurator, string, error) {
	wrap := func(dev tun.Device) tun.Device {
		return tundev.Wrap(ctx, dev, tundev.Options{Filter: a.filter, DNSAddr: magicdns.Addr, DNS: a.dns.Handle})
	}
	if !a.opts.Userspace {
		iface, err := netcfg.Create(a.opts.Interface)
		if err != nil {
			return nil, nil, "", err
		}
		a.net = osNetwork{}
		a.iface = iface
		return wrap(iface.TUN), iface, iface.Name(), nil
	}
	addr, err := a.meshAddress(ctx)
	if err != nil {
		return nil, nil, "", err
	}
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, netcfg.MTU)
	if err != nil {
		return nil, nil, "", fmt.Errorf("userspace network stack: %w", err)
	}
	a.net = stackNetwork{tnet}
	return wrap(dev), userspaceNet{addr}, "", nil
}

// errGotNetmap stops the one-shot netmap read in meshAddress.
var errGotNetmap = errors.New("got netmap")

// meshAddress returns this node's mesh address, from the state file or, for
// nodes registered by older versions, from one netmap.
func (a *agent) meshAddress(ctx context.Context) (netip.Addr, error) {
	a.mu.Lock()
	saved, token := a.st.Address, a.st.NodeToken
	a.mu.Unlock()
	if p, err := netip.ParsePrefix(saved); err == nil {
		return p.Addr(), nil
	}
	var addr netip.Addr
	err := a.client.Watch(ctx, token, &controlv1.WatchNetmapRequest{AdvertisedRoutes: a.opts.advertised()}, func(resp *controlv1.WatchNetmapResponse) error {
		if addrs := resp.GetSelf().GetAddresses(); len(addrs) > 0 {
			if p, err := netip.ParsePrefix(addrs[0]); err == nil {
				addr = p.Addr()
			}
		}
		return errGotNetmap
	})
	if !addr.IsValid() {
		return netip.Addr{}, fmt.Errorf("learn mesh address: %w", err)
	}
	return addr, nil
}

// resolve turns a peer name (bare or under the MagicDNS domain) or an IP
// address into an address, reporting whether it belongs to the mesh.
func (a *agent) resolve(host string) (netip.Addr, bool) {
	if ip, ok := a.dns.Lookup(host); ok {
		return ip, true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, a.prefix.IsValid() && a.prefix.Contains(ip)
	}
	ip, ok := a.peers[host]
	return ip, ok
}

// routed reports whether ip is reached through a peer's route (a subnet
// route or the exit node).
func (a *agent) routed(ip netip.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range a.routes {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// dialProxy connects SOCKS5 clients: mesh names and addresses, and
// destinations covered by routes in use (all of them, with an exit node),
// go through the mesh; anything else through the host's own network.
func (a *agent) dialProxy(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip, mesh := a.resolve(host); mesh {
		return a.net.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		a.mu.Lock()
		hasRoutes := len(a.routes) > 0
		a.mu.Unlock()
		if !hasRoutes {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			return nil, err
		}
		ip = ips[0]
	}
	target := net.JoinHostPort(ip.Unmap().String(), port)
	if a.routed(ip.Unmap()) {
		return a.net.DialContext(ctx, network, target)
	}
	return (&net.Dialer{}).DialContext(ctx, network, target)
}

// Ping implements localapi.Backend: it probes a peer's echo service through
// the mesh, from inside the agent so it works in userspace mode too.
func (a *agent) Ping(ctx context.Context, target string, count int, timeout time.Duration, fn func(pingsvc.Result)) (netip.Addr, error) {
	ip, mesh := a.resolve(target)
	if !mesh {
		return netip.Addr{}, fmt.Errorf("unknown peer %q", target)
	}
	conn, err := a.net.DialContext(ctx, "udp", netip.AddrPortFrom(ip, pingsvc.Port).String())
	if err != nil {
		return ip, err
	}
	defer conn.Close()
	return ip, pingsvc.Ping(ctx, conn, count, time.Second, timeout, fn)
}
