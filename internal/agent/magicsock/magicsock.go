// Package magicsock is a WireGuard conn.Bind that finds the best path to each
// peer. WireGuard addresses peers by public key (through a virtual endpoint);
// for every packet the bind picks a direct UDP address that answered a disco
// ping recently, and otherwise sends through the coordinator's relay. It also
// discovers this node's public address with STUN and punches holes through
// NATs with disco ping / call-me-maybe exchanges.
package magicsock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/sneakybugmaster/transporter/internal/netns"
	"github.com/sneakybugmaster/transporter/internal/relay"
	"github.com/sneakybugmaster/transporter/internal/stun"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

// Timing. A direct path is trusted for trustDuration after its last pong;
// pings every pingInterval keep a working path trusted.
const (
	pingInterval     = 5 * time.Second
	trustDuration    = 12 * time.Second
	pingTimeout      = 5 * time.Second
	callMeMaybeEvery = 10 * time.Second
	// sendProbeEvery rate-limits the extra probing triggered by traffic for
	// a peer that has no direct path yet.
	sendProbeEvery  = 2 * time.Second
	stunInterval    = 20 * time.Second
	localAddrsEvery = 30 * time.Second
	discoveredTTL   = 2 * time.Minute
	tickInterval    = time.Second
	// A new path must be this much faster to replace a working one, which
	// keeps the choice from flapping between paths of similar latency.
	switchFactor = 0.8

	maxCandidates = 32
	endpointPref  = "tp:"

	// Packets for a peer with no usable path yet (no trusted direct address
	// and the relay still connecting) wait briefly instead of being dropped.
	// Otherwise the first WireGuard handshake is lost and WireGuard waits 5s
	// before retrying. See Send for which side holds them.
	maxPending = 8
	pendingTTL = 3 * time.Second
)

// Options configures a Conn.
type Options struct {
	PrivateKey wgkey.Key
	Log        *slog.Logger
	// ExcludeInterfaces are left out of local endpoint discovery (the mesh
	// interface itself).
	ExcludeInterfaces []string
	// ExtraEndpoints are advertised in addition to discovered ones (e.g. a
	// manual port forward).
	ExtraEndpoints []netip.AddrPort
	// OnEndpoints is called (from its own goroutine) whenever the set of
	// endpoints this node should advertise changes.
	OnEndpoints func([]netip.AddrPort)
	// DisableLocalEndpoints skips interface addresses (used by tests that
	// need to force traffic through the relay).
	DisableLocalEndpoints bool
}

// PeerConfig describes a peer and the endpoints the coordinator knows for it.
type PeerConfig struct {
	Key       wgkey.Key
	Name      string
	Endpoints []netip.AddrPort
}

// Conn implements conn.Bind.
type Conn struct {
	opts Options
	log  *slog.Logger
	pub  wgkey.Key

	mu         sync.Mutex
	pc         *net.UDPConn
	port       uint16
	closed     chan struct{}
	peers      map[wgkey.Key]*peer
	byAddr     map[netip.AddrPort]*peer // addresses proven by disco
	pings      map[txID]pendingPing
	relay      *relay.Client
	stunServer netip.AddrPort
	stunTx     map[stun.TxID]time.Time
	lastSTUN   time.Time
	reflexive  netip.AddrPort
	local      []netip.AddrPort
	lastLocal  time.Time
	meshPrefix netip.Prefix
	advertised []netip.AddrPort
	relayIn    chan relay.Packet
	stopRelay  context.CancelFunc
}

type peer struct {
	cfg        PeerConfig
	ep         *Endpoint
	shared     [32]byte
	candidates map[netip.AddrPort]*candidate
	best       netip.AddrPort
	lastPing   time.Time
	lastCMM    time.Time
	lastCMMIn  time.Time
	pending    []pendingPacket
}

type pendingPacket struct {
	b     []byte
	added time.Time
}

type candidate struct {
	fromNetmap bool
	added      time.Time
	lastPong   time.Time
	latency    time.Duration
}

type pendingPing struct {
	peer *peer
	addr netip.AddrPort
	sent time.Time
}

// New returns a Conn. It does nothing until WireGuard opens it.
func New(opts Options) *Conn {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Conn{
		opts:    opts,
		log:     opts.Log.With("component", "magicsock"),
		pub:     opts.PrivateKey.Public(),
		peers:   map[wgkey.Key]*peer{},
		byAddr:  map[netip.AddrPort]*peer{},
		pings:   map[txID]pendingPing{},
		stunTx:  map[stun.TxID]time.Time{},
		relayIn: make(chan relay.Packet, 256),
	}
}

// Endpoint is WireGuard's handle on a peer: a key, not an address.
type Endpoint struct {
	key wgkey.Key
	c   *Conn
}

var _ conn.Endpoint = (*Endpoint)(nil)

func (e *Endpoint) ClearSrc()           {}
func (e *Endpoint) SrcToString() string { return "" }
func (e *Endpoint) DstToString() string { return EndpointString(e.key) }
func (e *Endpoint) DstToBytes() []byte  { return e.key[:] }
func (e *Endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *Endpoint) DstIP() netip.Addr {
	e.c.mu.Lock()
	defer e.c.mu.Unlock()
	if p := e.c.peers[e.key]; p != nil && p.best.IsValid() {
		return p.best.Addr()
	}
	return netip.Addr{}
}

// EndpointString is the value to give WireGuard as a peer's "endpoint".
func EndpointString(k wgkey.Key) string { return endpointPref + k.Hex() }

// ParseEndpoint implements conn.Bind.
func (c *Conn) ParseEndpoint(s string) (conn.Endpoint, error) {
	h, ok := strings.CutPrefix(s, endpointPref)
	if !ok {
		return nil, fmt.Errorf("magicsock: endpoint %q is not a peer key", s)
	}
	k, err := wgkey.ParseHex(h)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if p := c.peers[k]; p != nil {
		return p.ep, nil
	}
	return &Endpoint{key: k, c: c}, nil
}

// BatchSize implements conn.Bind.
func (c *Conn) BatchSize() int { return 1 }

// SetMark implements conn.Bind.
func (c *Conn) SetMark(uint32) error { return nil }

// Open implements conn.Bind: it binds the UDP socket and starts discovery.
func (c *Conn) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pc != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	// The socket bypasses the tunnel when an exit node routes everything
	// else into it.
	lpc, err := netns.ListenConfig().ListenPacket(context.Background(), "udp4", ":"+strconv.Itoa(int(port)))
	if err != nil {
		return nil, 0, err
	}
	pc := lpc.(*net.UDPConn)
	c.pc = pc
	c.port = uint16(pc.LocalAddr().(*net.UDPAddr).Port) //nolint:gosec // ports fit in uint16
	c.closed = make(chan struct{})
	c.lastLocal, c.lastSTUN = time.Time{}, time.Time{}
	go c.loop(c.closed)
	return []conn.ReceiveFunc{c.receiveUDP(pc), c.receiveRelay(c.closed)}, c.port, nil
}

// Close implements conn.Bind.
func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pc == nil {
		return nil
	}
	err := c.pc.Close()
	close(c.closed)
	c.pc = nil
	return err
}

// Shutdown stops the relay client; call it after WireGuard is closed.
func (c *Conn) Shutdown() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopRelay != nil {
		c.stopRelay()
		c.stopRelay = nil
	}
}

// LocalPort returns the bound UDP port (0 if closed).
func (c *Conn) LocalPort() uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.port
}

// SetRelay connects to the relay on the coordinator at baseURL.
func (c *Conn) SetRelay(baseURL, token string) error {
	rc, err := relay.NewClient(baseURL, token, c.log)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	if c.stopRelay != nil {
		c.stopRelay()
	}
	c.relay, c.stopRelay = rc, cancel
	c.mu.Unlock()
	go rc.Run(ctx)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case p := <-rc.Recv():
				select {
				case c.relayIn <- p:
				default:
				}
			}
		}
	}()
	return nil
}

// SetSTUNServer sets the STUN server used to learn the public address.
func (c *Conn) SetSTUNServer(addr netip.AddrPort) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if addr != c.stunServer {
		c.stunServer, c.lastSTUN = addr, time.Time{}
	}
}

// SetMeshPrefix excludes mesh addresses from local endpoint discovery.
func (c *Conn) SetMeshPrefix(p netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.meshPrefix = p
}

// SetPeers replaces the peer set and their netmap endpoints.
func (c *Conn) SetPeers(peers []PeerConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	seen := map[wgkey.Key]bool{}
	for _, cfg := range peers {
		seen[cfg.Key] = true
		p := c.peers[cfg.Key]
		if p == nil {
			shared, err := discoSharedKey(c.opts.PrivateKey, cfg.Key)
			if err != nil {
				c.log.Warn("bad peer key", "peer", cfg.Name, "err", err)
				continue
			}
			p = &peer{ep: &Endpoint{key: cfg.Key, c: c}, shared: shared, candidates: map[netip.AddrPort]*candidate{}}
			c.peers[cfg.Key] = p
		}
		p.cfg = cfg
		for addr, cd := range p.candidates {
			if cd.fromNetmap && !slices.Contains(cfg.Endpoints, addr) {
				c.dropCandidateLocked(p, addr)
			}
		}
		for _, ep := range cfg.Endpoints {
			if cd := p.candidates[ep]; cd != nil {
				cd.fromNetmap = true
			} else if len(p.candidates) < maxCandidates {
				p.candidates[ep] = &candidate{fromNetmap: true, added: now}
				p.lastPing = time.Time{} // probe new candidates right away
			}
		}
	}
	for k, p := range c.peers {
		if !seen[k] {
			for addr := range p.candidates {
				c.dropCandidateLocked(p, addr)
			}
			delete(c.peers, k)
		}
	}
}

func (c *Conn) dropCandidateLocked(p *peer, addr netip.AddrPort) {
	delete(p.candidates, addr)
	if c.byAddr[addr] == p {
		delete(c.byAddr, addr)
	}
	if p.best == addr {
		p.best = netip.AddrPort{}
	}
}

// Send implements conn.Bind.
func (c *Conn) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*Endpoint)
	if !ok {
		return errors.New("magicsock: foreign endpoint")
	}
	c.mu.Lock()
	p := c.peers[e.key]
	pc := c.pc
	rc := c.relay
	var (
		direct netip.AddrPort
		probes []outPacket
	)
	if p != nil {
		now := time.Now()
		direct = c.directPathLocked(p, now)
		if !direct.IsValid() && len(p.candidates) > 0 && now.Sub(p.lastPing) >= sendProbeEvery {
			// WireGuard wants to talk to this peer now: probe right away
			// rather than wait for the next discovery round.
			probes = c.pingPeerLocked(p, now)
		}
	}
	c.mu.Unlock()
	if probes != nil {
		c.write(probes)
	}
	if p == nil || pc == nil {
		return nil // unknown peer or closed: drop; WireGuard retransmits
	}
	if direct.IsValid() {
		for _, b := range bufs {
			if _, err := pc.WriteToUDPAddrPort(b, direct); err != nil {
				return err
			}
		}
		return nil
	}
	if rc != nil && rc.Connected() {
		for _, b := range bufs {
			_ = rc.Send(context.Background(), e.key, b) // best effort
		}
		return nil
	}
	// No path at all yet: hold the packets until one appears, but only on
	// one side of each pair. If both sides held their handshake initiations
	// and released them together, each would answer the other's and discard
	// its own, and neither handshake would complete until WireGuard retries
	// 5s later. The side with the lower key holds; the other drops as usual
	// and completes the handshake its peer starts.
	if bytes.Compare(c.pub[:], e.key[:]) > 0 {
		return nil
	}
	c.mu.Lock()
	now := time.Now()
	for _, b := range bufs {
		if len(p.pending) == maxPending {
			p.pending = p.pending[1:]
		}
		p.pending = append(p.pending, pendingPacket{b: slices.Clone(b), added: now})
	}
	c.mu.Unlock()
	return nil
}

// takePendingLocked returns p's queued packets that are still fresh.
func takePendingLocked(p *peer, now time.Time) [][]byte {
	var out [][]byte
	for _, pp := range p.pending {
		if now.Sub(pp.added) <= pendingTTL {
			out = append(out, pp.b)
		}
	}
	p.pending = nil
	return out
}

// directPathLocked returns the trusted direct address for p, if any.
func (c *Conn) directPathLocked(p *peer, now time.Time) netip.AddrPort {
	if !p.best.IsValid() {
		return netip.AddrPort{}
	}
	cd := p.candidates[p.best]
	if cd == nil || now.Sub(cd.lastPong) > trustDuration {
		return netip.AddrPort{}
	}
	return p.best
}

func (c *Conn) receiveUDP(pc *net.UDPConn) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, src, err := pc.ReadFromUDPAddrPort(bufs[0])
			if err != nil {
				return 0, err
			}
			src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
			b := bufs[0][:n]
			switch {
			case stun.Is(b):
				c.handleSTUN(b)
				continue
			case isDisco(b):
				c.handleDisco(b, src, nil)
				continue
			}
			c.mu.Lock()
			p := c.byAddr[src]
			c.mu.Unlock()
			if p == nil {
				continue // not from an address a peer proved it owns
			}
			sizes[0], eps[0] = n, p.ep
			return 1, nil
		}
	}
}

func (c *Conn) receiveRelay(closed chan struct{}) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			select {
			case <-closed:
				return 0, net.ErrClosed
			case pkt := <-c.relayIn:
				if isDisco(pkt.Payload) {
					from := pkt.From
					c.handleDisco(pkt.Payload, netip.AddrPort{}, &from)
					continue
				}
				c.mu.Lock()
				p := c.peers[pkt.From]
				c.mu.Unlock()
				if p == nil || len(pkt.Payload) > len(bufs[0]) {
					continue
				}
				sizes[0] = copy(bufs[0], pkt.Payload)
				eps[0] = p.ep
				return 1, nil
			}
		}
	}
}
