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
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/sneakybugmaster/transporter/internal/agent/controlclient"
	"github.com/sneakybugmaster/transporter/internal/agent/engine"
	"github.com/sneakybugmaster/transporter/internal/agent/localapi"
	"github.com/sneakybugmaster/transporter/internal/agent/magicsock"
	"github.com/sneakybugmaster/transporter/internal/agent/netcfg"
	"github.com/sneakybugmaster/transporter/internal/agent/pingsvc"
	"github.com/sneakybugmaster/transporter/internal/agent/socks5"
	"github.com/sneakybugmaster/transporter/internal/agent/state"
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
	Log    *slog.Logger
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	a := &agent{opts: opts, log: opts.Log, client: client, st: st, cancel: cancel, runCtx: ctx}

	if !st.Registered(opts.CoordinatorURL) {
		if err := a.registerWithRetry(ctx); err != nil {
			return err
		}
	}

	tunDev, netCfg, ifName, err := a.setupInterface(ctx)
	if err != nil {
		return err
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

	return a.watchLoop(ctx)
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

		err := a.client.Watch(ctx, token, a.endpoints(), a.applyNetmap)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, controlclient.ErrUnauthenticated) {
			a.mu.Lock()
			retry := !a.registered && a.opts.AuthKey != ""
			a.mu.Unlock()
			if !retry {
				return fmt.Errorf("coordinator rejected this node (was it deleted?); run again with --authkey to re-enroll: %w", err)
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
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", u.Hostname())
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
	if err := a.eng.Apply(nm); err != nil {
		return err
	}
	a.configureNAT(resp)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.lastErr = ""
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
	return nil
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
	return nm, nil
}

func convertNode(p *controlv1.Node) (engine.Node, error) {
	key, err := wgkey.FromBytes(p.GetWireguardPublicKey())
	if err != nil {
		return engine.Node{}, err
	}
	n := engine.Node{ID: p.GetId(), Name: p.GetName(), Key: key, Online: p.GetOnline()}
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
	if !a.opts.Userspace {
		iface, err := netcfg.Create(a.opts.Interface)
		if err != nil {
			return nil, nil, "", err
		}
		a.net = osNetwork{}
		return iface.TUN, iface, iface.Name(), nil
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
	return dev, userspaceNet{addr}, "", nil
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
	err := a.client.Watch(ctx, token, nil, func(resp *controlv1.WatchNetmapResponse) error {
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

// resolve turns a peer name or IP address into an address, reporting whether
// it belongs to the mesh.
func (a *agent) resolve(host string) (netip.Addr, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip, a.prefix.IsValid() && a.prefix.Contains(ip)
	}
	ip, ok := a.peers[host]
	return ip, ok
}

// dialProxy connects SOCKS5 clients: mesh names and addresses go through the
// mesh, anything else through the host's own network.
func (a *agent) dialProxy(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if ip, mesh := a.resolve(host); mesh {
		return a.net.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
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
