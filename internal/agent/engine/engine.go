// Package engine owns the WireGuard device and keeps it in sync with the
// netmap pushed by the coordinator. Path selection (direct or relayed) is
// delegated to magicsock.
package engine

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/sneakybugmaster/transporter/internal/agent/magicsock"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

// NetConfigurator applies OS-level interface settings.
type NetConfigurator interface {
	// SetAddress assigns the overlay address to the interface; its prefix
	// length covers the whole mesh so the OS routes mesh traffic to it.
	SetAddress(addr netip.Prefix) error
	// SetRoutes makes the OS send traffic for these prefixes (outside the
	// mesh prefix) into the interface.
	SetRoutes(routes []netip.Prefix) error
}

// Config configures an Engine.
type Config struct {
	PrivateKey wgkey.Key
	// ListenPort is the UDP port for WireGuard; 0 picks a random port.
	ListenPort uint16
	TUN        tun.Device
	// Conn carries WireGuard's packets; it must use the same PrivateKey.
	Conn *magicsock.Conn
	// Net configures the interface; nil skips OS configuration (tests).
	Net NetConfigurator
	Log *slog.Logger
}

// Netmap is the engine's view of the mesh.
type Netmap struct {
	Self   Node
	Prefix netip.Prefix
	Peers  []Node
	// Routes outside Prefix that the OS should send into the mesh: routes
	// of peers (in their Addresses) and the MagicDNS address.
	Routes []netip.Prefix
}

// Node is a mesh member as described by the coordinator.
type Node struct {
	ID   string
	Name string
	Key  wgkey.Key
	// Addresses are the prefixes WireGuard routes to the node: its mesh
	// address plus any of its routes this node uses.
	Addresses []netip.Prefix
	Endpoints []netip.AddrPort
	Online    bool
	// Routes are the subnet routes the node offers, used or not.
	Routes []netip.Prefix
}

// Engine drives a WireGuard device.
type Engine struct {
	log  *slog.Logger
	dev  *device.Device
	conn *magicsock.Conn
	net  NetConfigurator

	mu      sync.Mutex
	self    Node
	prefix  netip.Prefix
	addr    netip.Prefix
	routes  []netip.Prefix
	peers   map[wgkey.Key]Node
	applied bool
}

// New creates the WireGuard device and brings it up.
func New(cfg Config) (*Engine, error) {
	if cfg.TUN == nil || cfg.Conn == nil {
		return nil, errors.New("engine: TUN device and magicsock conn required")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	wgLog := log.With("component", "wireguard")
	dev := device.NewDevice(cfg.TUN, cfg.Conn, &device.Logger{
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
		conn:  cfg.Conn,
		net:   cfg.Net,
		peers: map[wgkey.Key]Node{},
	}, nil
}

// Close tears down the device (and with it the TUN interface).
func (e *Engine) Close() { e.dev.Close() }

// ListenPort returns the UDP port WireGuard is bound to.
func (e *Engine) ListenPort() uint16 { return e.conn.LocalPort() }

// Apply reconciles the device with a new netmap.
func (e *Engine) Apply(nm Netmap) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.self, e.prefix, e.applied = nm.Self, nm.Prefix, true
	e.conn.SetMeshPrefix(nm.Prefix)
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

	if e.net != nil && !slices.Equal(nm.Routes, e.routes) {
		if err := e.net.SetRoutes(nm.Routes); err != nil {
			return fmt.Errorf("set routes: %w", err)
		}
		e.routes = slices.Clone(nm.Routes)
		e.log.Info("routes set", "routes", nm.Routes)
	}

	var (
		cfg     strings.Builder
		wanted  = map[wgkey.Key]bool{}
		configs []magicsock.PeerConfig
	)
	for _, n := range nm.Peers {
		if n.Key == nm.Self.Key {
			continue
		}
		wanted[n.Key] = true
		configs = append(configs, magicsock.PeerConfig{Key: n.Key, Name: n.Name, Endpoints: n.Endpoints})
		old, exists := e.peers[n.Key]
		e.peers[n.Key] = n
		if exists && slices.Equal(old.Addresses, n.Addresses) {
			continue
		}
		if !exists {
			e.log.Info("peer added", "peer", n.Name, "addresses", n.Addresses)
		}
		cfg.WriteString(peerConfig(n.Key, n.Addresses, !exists))
	}
	for key, n := range e.peers {
		if !wanted[key] {
			cfg.WriteString(removePeerConfig(key))
			delete(e.peers, key)
			e.log.Info("peer removed", "peer", n.Name)
		}
	}
	// Tell magicsock about new peers before WireGuard can try to reach them.
	e.conn.SetPeers(configs)
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
	Endpoints  []string     `json:"endpoints"`
	Peers      []PeerStatus `json:"peers"`
}

// PeerStatus describes one peer.
type PeerStatus struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	PublicKey string   `json:"publicKey"`
	Online    bool     `json:"online"`
	// Path is "direct", "relay" or "" when the peer is unreachable.
	Path          string    `json:"path"`
	Endpoint      string    `json:"endpoint,omitempty"`
	LatencyMs     float64   `json:"latencyMs,omitempty"`
	Endpoints     []string  `json:"endpoints"`
	LastHandshake time.Time `json:"lastHandshake,omitzero"`
	RxBytes       uint64    `json:"rxBytes"`
	TxBytes       uint64    `json:"txBytes"`
	// Routes the peer offers (0.0.0.0/0 for an exit node).
	Routes []string `json:"routes"`
}

// Status returns the current state of the engine.
func (e *Engine) Status() (Status, error) {
	st, err := e.stats()
	if err != nil {
		return Status{}, err
	}
	paths := e.conn.Paths()
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Status{
		Name:       e.self.Name,
		Addresses:  prefixStrings(e.self.Addresses),
		PublicKey:  e.self.Key.String(),
		ListenPort: e.conn.LocalPort(),
		Connected:  e.applied,
		Endpoints:  []string{},
		Peers:      []PeerStatus{},
	}
	if e.prefix.IsValid() {
		s.Prefix = e.prefix.String()
	}
	for _, ep := range e.conn.Endpoints() {
		s.Endpoints = append(s.Endpoints, ep.String())
	}
	for key, n := range e.peers {
		pst := st.peers[key]
		path := paths[key]
		p := PeerStatus{
			ID:            n.ID,
			Name:          n.Name,
			Routes:        prefixStrings(n.Routes),
			Addresses:     prefixStrings(n.Addresses),
			PublicKey:     key.String(),
			Online:        n.Online,
			Path:          path.Kind,
			Endpoints:     []string{},
			LastHandshake: pst.lastHandshake,
			RxBytes:       pst.rxBytes,
			TxBytes:       pst.txBytes,
		}
		if path.Addr.IsValid() {
			p.Endpoint = path.Addr.String()
			p.LatencyMs = float64(path.Latency.Microseconds()) / 1000
		}
		for _, ep := range n.Endpoints {
			p.Endpoints = append(p.Endpoints, ep.String())
		}
		s.Peers = append(s.Peers, p)
	}
	slices.SortFunc(s.Peers, func(a, b PeerStatus) int { return strings.Compare(a.Name, b.Name) })
	return s, nil
}

func prefixStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}
