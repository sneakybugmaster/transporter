// Package engine owns the WireGuard device and keeps it in sync with the
// netmap pushed by the coordinator.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/sneakybugmaster/transporter/internal/agent/wgkey"
)

const (
	// staleHandshake is how old a handshake may get before the peer's path is
	// considered broken. WireGuard re-handshakes every two minutes on an
	// active session (which persistent keepalives guarantee).
	staleHandshake = 3 * time.Minute
	// endpointTryTime is how long to wait for a handshake on one candidate
	// endpoint before trying the next. WireGuard retries handshakes every 5s.
	endpointTryTime = 6 * time.Second
	rotateInterval  = 2 * time.Second
)

// NetConfigurator applies OS-level interface settings.
type NetConfigurator interface {
	// SetAddress assigns the overlay address to the interface; its prefix
	// length covers the whole mesh so the OS routes mesh traffic to it.
	SetAddress(addr netip.Prefix) error
}

// Config configures an Engine.
type Config struct {
	PrivateKey wgkey.Key
	// ListenPort is the UDP port for WireGuard; 0 picks a random port.
	ListenPort uint16
	TUN        tun.Device
	// Net configures the interface; nil skips OS configuration (tests).
	Net NetConfigurator
	// Bind overrides the UDP transport; nil uses the platform default.
	Bind conn.Bind
	Log  *slog.Logger
}

// Netmap is the engine's view of the mesh.
type Netmap struct {
	Self   Node
	Prefix netip.Prefix
	Peers  []Node
}

// Node is a mesh member as described by the coordinator.
type Node struct {
	ID        string
	Name      string
	Key       wgkey.Key
	Addresses []netip.Prefix
	Endpoints []netip.AddrPort
	Online    bool
}

// Engine drives a WireGuard device.
type Engine struct {
	log  *slog.Logger
	dev  *device.Device
	port uint16
	net  NetConfigurator
	now  func() time.Time

	mu      sync.Mutex
	self    Node
	prefix  netip.Prefix
	addr    netip.Prefix
	peers   map[wgkey.Key]*peerState
	applied bool
}

type peerState struct {
	node        Node
	endpointIdx int       // index into node.Endpoints we last configured
	endpointAt  time.Time // when we last configured an endpoint
}

// New creates the WireGuard device and brings it up.
func New(cfg Config) (*Engine, error) {
	if cfg.TUN == nil {
		return nil, errors.New("engine: TUN device required")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	bind := cfg.Bind
	if bind == nil {
		bind = conn.NewDefaultBind()
	}
	if cfg.ListenPort == 0 {
		// Pick a concrete port: wireguard-go does not report kernel-chosen
		// ports, and on hosts without IPv6 it reports 0 for any port.
		port, err := freeUDPPort()
		if err != nil {
			return nil, err
		}
		cfg.ListenPort = port
	}
	wgLog := log.With("component", "wireguard")
	dev := device.NewDevice(cfg.TUN, bind, &device.Logger{
		Verbosef: func(format string, args ...any) { wgLog.Debug(fmt.Sprintf(format, args...)) },
		Errorf:   func(format string, args ...any) { wgLog.Warn(fmt.Sprintf(format, args...)) },
	})
	err := dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d\n", cfg.PrivateKey.Hex(), cfg.ListenPort))
	if err == nil {
		err = dev.Up()
	}
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure wireguard device: %w", err)
	}
	return &Engine{
		log:   log,
		dev:   dev,
		port:  cfg.ListenPort,
		net:   cfg.Net,
		now:   time.Now,
		peers: map[wgkey.Key]*peerState{},
	}, nil
}

// Close tears down the device (and with it the TUN interface).
func (e *Engine) Close() { e.dev.Close() }

// ListenPort returns the UDP port WireGuard is bound to.
func (e *Engine) ListenPort() uint16 { return e.port }

// Apply reconciles the device with a new netmap.
func (e *Engine) Apply(nm Netmap) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.self, e.prefix, e.applied = nm.Self, nm.Prefix, true
	if len(nm.Self.Addresses) > 0 && e.net != nil {
		addr := netip.PrefixFrom(nm.Self.Addresses[0].Addr(), nm.Prefix.Bits())
		if addr != e.addr {
			if err := e.net.SetAddress(addr); err != nil {
				return fmt.Errorf("set interface address: %w", err)
			}
			e.addr = addr
			e.log.Info("interface address set", "address", addr)
		}
	}

	var cfg strings.Builder
	wanted := map[wgkey.Key]bool{}
	now := e.now()
	for _, n := range nm.Peers {
		if n.Key == nm.Self.Key {
			continue
		}
		wanted[n.Key] = true
		ps, exists := e.peers[n.Key]
		if exists && sameNode(ps.node, n) {
			ps.node = n // refresh Online etc.
			continue
		}

		var endpoint netip.AddrPort
		switch {
		case !exists:
			ps = &peerState{}
			e.peers[n.Key] = ps
			if len(n.Endpoints) > 0 {
				endpoint = n.Endpoints[0]
			}
			e.log.Info("peer added", "peer", n.Name, "addresses", n.Addresses, "endpoints", n.Endpoints)
		case !slices.Equal(ps.node.Endpoints, n.Endpoints):
			// Keep the endpoint we were using if it is still a candidate.
			cur := currentEndpoint(ps)
			if i := slices.Index(n.Endpoints, cur); i >= 0 {
				ps.endpointIdx = i
			} else if len(n.Endpoints) > 0 {
				endpoint = n.Endpoints[0]
			}
			e.log.Info("peer updated", "peer", n.Name, "endpoints", n.Endpoints)
		}
		if endpoint.IsValid() {
			ps.endpointIdx, ps.endpointAt = 0, now
		}
		ps.node = n
		cfg.WriteString(peerConfig(n.Key, n.Addresses, endpoint))
	}
	for key, ps := range e.peers {
		if !wanted[key] {
			cfg.WriteString(removePeerConfig(key))
			delete(e.peers, key)
			e.log.Info("peer removed", "peer", ps.node.Name)
		}
	}
	if cfg.Len() == 0 {
		return nil
	}
	return e.dev.IpcSet(cfg.String())
}

// Run rotates through candidate endpoints for peers whose handshakes have
// gone stale, until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	t := time.NewTicker(rotateInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.rotateEndpoints(); err != nil {
				e.log.Warn("endpoint rotation", "err", err)
			}
		}
	}
}

func (e *Engine) rotateEndpoints() error {
	st, err := e.stats()
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	var cfg strings.Builder
	for key, ps := range e.peers {
		n := len(ps.node.Endpoints)
		if n == 0 {
			continue
		}
		hs := st.peers[key].lastHandshake
		if !hs.IsZero() && now.Sub(hs) < staleHandshake {
			// Working path. WireGuard may have roamed to an endpoint the
			// peer contacted us from; remember it if it is a candidate.
			if i := slices.Index(ps.node.Endpoints, st.peers[key].endpoint); i >= 0 {
				ps.endpointIdx = i
			}
			continue
		}
		if n == 1 || now.Sub(ps.endpointAt) < endpointTryTime {
			continue
		}
		ps.endpointIdx = (ps.endpointIdx + 1) % n
		ps.endpointAt = now
		ep := ps.node.Endpoints[ps.endpointIdx]
		e.log.Debug("trying next endpoint", "peer", ps.node.Name, "endpoint", ep)
		cfg.WriteString(endpointConfig(key, ep))
	}
	if cfg.Len() == 0 {
		return nil
	}
	return e.dev.IpcSet(cfg.String())
}

func (e *Engine) stats() (deviceStats, error) {
	s, err := e.dev.IpcGet()
	if err != nil {
		return deviceStats{}, err
	}
	return parseStats(s)
}

// Status is a snapshot for display.
type Status struct {
	Name       string       `json:"name"`
	Addresses  []string     `json:"addresses"`
	PublicKey  string       `json:"publicKey"`
	ListenPort uint16       `json:"listenPort"`
	Prefix     string       `json:"networkPrefix"`
	Connected  bool         `json:"connected"`
	Peers      []PeerStatus `json:"peers"`
}

// PeerStatus describes one peer.
type PeerStatus struct {
	Name          string    `json:"name"`
	Addresses     []string  `json:"addresses"`
	PublicKey     string    `json:"publicKey"`
	Online        bool      `json:"online"`
	Endpoint      string    `json:"endpoint,omitempty"`
	Endpoints     []string  `json:"endpoints"`
	LastHandshake time.Time `json:"lastHandshake,omitzero"`
	RxBytes       uint64    `json:"rxBytes"`
	TxBytes       uint64    `json:"txBytes"`
}

// Status returns the current state of the engine.
func (e *Engine) Status() (Status, error) {
	st, err := e.stats()
	if err != nil {
		return Status{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Status{
		Name:       e.self.Name,
		Addresses:  prefixStrings(e.self.Addresses),
		PublicKey:  e.self.Key.String(),
		ListenPort: e.port,
		Connected:  e.applied,
		Peers:      []PeerStatus{},
	}
	if e.prefix.IsValid() {
		s.Prefix = e.prefix.String()
	}
	for key, ps := range e.peers {
		pst := st.peers[key]
		p := PeerStatus{
			Name:          ps.node.Name,
			Addresses:     prefixStrings(ps.node.Addresses),
			PublicKey:     key.String(),
			Online:        ps.node.Online,
			Endpoints:     []string{},
			LastHandshake: pst.lastHandshake,
			RxBytes:       pst.rxBytes,
			TxBytes:       pst.txBytes,
		}
		if pst.endpoint.IsValid() {
			p.Endpoint = pst.endpoint.String()
		}
		for _, ep := range ps.node.Endpoints {
			p.Endpoints = append(p.Endpoints, ep.String())
		}
		s.Peers = append(s.Peers, p)
	}
	slices.SortFunc(s.Peers, func(a, b PeerStatus) int { return strings.Compare(a.Name, b.Name) })
	return s, nil
}

func freeUDPPort() (uint16, error) {
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port), nil //nolint:gosec // ports fit in uint16
}

func sameNode(a, b Node) bool {
	return a.Key == b.Key &&
		slices.Equal(a.Addresses, b.Addresses) &&
		slices.Equal(a.Endpoints, b.Endpoints)
}

func currentEndpoint(ps *peerState) netip.AddrPort {
	if ps.endpointIdx < len(ps.node.Endpoints) {
		return ps.node.Endpoints[ps.endpointIdx]
	}
	return netip.AddrPort{}
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}
