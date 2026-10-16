// Package agent runs a mesh node: it enrolls with the coordinator, keeps the
// WireGuard engine in sync with the netmap and serves the local API.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent/controlclient"
	"github.com/sneakybugmaster/transporter/internal/agent/engine"
	"github.com/sneakybugmaster/transporter/internal/agent/localapi"
	"github.com/sneakybugmaster/transporter/internal/agent/netcfg"
	"github.com/sneakybugmaster/transporter/internal/agent/pingsvc"
	"github.com/sneakybugmaster/transporter/internal/agent/state"
	"github.com/sneakybugmaster/transporter/internal/agent/wgkey"
	controlv1 "github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1"
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
	Log                *slog.Logger
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
	iface  *netcfg.Interface
	cancel context.CancelFunc

	mu         sync.Mutex
	st         *state.State
	prefix     netip.Prefix
	selfAddr   netip.Addr
	stopPing   context.CancelFunc
	lastErr    string
	runCtx     context.Context
	registered bool // registered during this run
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
		if err := a.register(ctx); err != nil {
			return err
		}
	}

	a.iface, err = netcfg.Create(opts.Interface)
	if err != nil {
		return err
	}
	a.eng, err = engine.New(engine.Config{
		PrivateKey: st.PrivateKey,
		ListenPort: opts.ListenPort,
		TUN:        a.iface.TUN,
		Net:        a.iface,
		Log:        opts.Log,
	})
	if err != nil {
		return err
	}
	defer a.eng.Close()
	a.log.Info("wireguard up", "interface", a.iface.Name(), "listenPort", a.eng.ListenPort(), "publicKey", st.PrivateKey.Public())

	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	wg.Go(func() { a.eng.Run(ctx) })
	wg.Go(func() {
		sock := filepath.Join(opts.StateDir, localapi.SocketName)
		if err := localapi.Serve(ctx, sock, a); err != nil {
			a.log.Error("local API", "err", err)
		}
	})

	return a.watchLoop(ctx)
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
	a.registered = true
	err = a.st.Save(a.opts.StateDir)
	a.mu.Unlock()
	if err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	a.log.Info("registered", "name", resp.GetNode().GetName(), "addresses", resp.GetNode().GetAddresses())
	return nil
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
			if err := a.register(ctx); err != nil {
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
	a.mu.Lock()
	prefix := a.prefix
	a.mu.Unlock()
	port := a.eng.ListenPort()

	var out []string
	for _, ep := range a.opts.AdvertiseEndpoints {
		out = append(out, ep.String())
	}
	local, err := netcfg.LocalEndpoints(port, prefix, a.iface.Name())
	if err != nil {
		a.log.Warn("list local endpoints", "err", err)
	}
	for _, ep := range local {
		out = append(out, ep.String())
	}
	// Leave room for the address the coordinator observes.
	if len(out) > 15 {
		out = out[:15]
	}
	return out
}

func (a *agent) applyNetmap(resp *controlv1.WatchNetmapResponse) error {
	nm, err := a.convert(resp)
	if err != nil {
		return err
	}
	if err := a.eng.Apply(nm); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	a.prefix = nm.Prefix
	a.lastErr = ""
	a.registered = false // a fresh token works again; allow re-registering later
	if len(nm.Self.Addresses) > 0 {
		if addr := nm.Self.Addresses[0].Addr(); addr != a.selfAddr {
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
		if err := pingsvc.Serve(ctx, addr); err != nil {
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
