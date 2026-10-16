package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/sneakybugmaster/transporter/internal/agent/magicsock"
	"github.com/sneakybugmaster/transporter/internal/relay"
	"github.com/sneakybugmaster/transporter/internal/stun"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

var (
	prefix  = netip.MustParsePrefix("100.64.0.0/10")
	discard = slog.New(slog.NewTextHandler(io.Discard, nil))
)

type testNode struct {
	eng  *Engine
	conn *magicsock.Conn
	tun  *tuntest.ChannelTUN
	// recv receives packets WireGuard writes to the TUN. It is drained from
	// tun.Inbound continuously: the channel TUN blocks writers (unlike a
	// real one), and a writer stuck on a stray retry would make removing
	// that peer hang.
	recv chan []byte
	node Node
	net  *fakeNet
}

type fakeNet struct{ addrs []netip.Prefix }

func (f *fakeNet) SetAddress(p netip.Prefix) error {
	f.addrs = append(f.addrs, p)
	return nil
}

// relayEnv is an in-process coordinator relay.
type relayEnv struct {
	url  string
	mu   sync.Mutex
	keys map[string]wgkey.Key
}

func newRelay(t *testing.T) *relayEnv {
	t.Helper()
	r := &relayEnv{keys: map[string]wgkey.Key{}}
	srv := relay.NewServer(func(_ context.Context, tok string) (wgkey.Key, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		k, ok := r.keys[tok]
		if !ok {
			return wgkey.Key{}, fmt.Errorf("unknown token")
		}
		return k, nil
	}, 0, 0, discard)
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	r.url = hs.URL
	return r
}

func (r *relayEnv) join(t *testing.T, n *testNode) {
	t.Helper()
	tok := "tok-" + n.node.Name
	r.mu.Lock()
	r.keys[tok] = n.node.Key
	r.mu.Unlock()
	if err := n.conn.SetRelay(r.url, tok); err != nil {
		t.Fatal(err)
	}
}

func newTestNode(t *testing.T, name, ip string, opts magicsock.Options) *testNode {
	t.Helper()
	key, err := wgkey.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	opts.PrivateKey, opts.Log = key, discard
	c := magicsock.New(opts)
	ct := tuntest.NewChannelTUN()
	fn := &fakeNet{}
	eng, err := New(Config{PrivateKey: key, TUN: ct.TUN(), Conn: c, Net: fn, Log: discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		eng.Close()
		c.Shutdown()
	})
	port := eng.ListenPort()
	if port == 0 {
		t.Fatal("listen port is 0")
	}
	recv := make(chan []byte, 1024)
	go func() {
		for pkt := range ct.Inbound {
			select {
			case recv <- pkt:
			default:
			}
		}
	}()
	return &testNode{
		eng:  eng,
		conn: c,
		tun:  ct,
		recv: recv,
		net:  fn,
		node: Node{
			Name:      name,
			Key:       key.Public(),
			Addresses: []netip.Prefix{netip.MustParsePrefix(ip + "/32")},
			Endpoints: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)},
			Online:    true,
		},
	}
}

func meshNetmap(self *testNode, all ...*testNode) Netmap {
	nm := Netmap{Self: self.node, Prefix: prefix}
	for _, n := range all {
		if n != self {
			nm.Peers = append(nm.Peers, n.node)
		}
	}
	return nm
}

func apply(t *testing.T, all ...*testNode) {
	t.Helper()
	for _, n := range all {
		if err := n.eng.Apply(meshNetmap(n, all...)); err != nil {
			t.Fatal(err)
		}
	}
}

// sendPing injects an ICMP echo at src's TUN and waits for it at dst's TUN.
func sendPing(t *testing.T, src, dst *testNode, timeout time.Duration) {
	t.Helper()
	pkt := tuntest.Ping(dst.node.Addresses[0].Addr(), src.node.Addresses[0].Addr())
	deadline := time.After(timeout)
	retry := time.NewTicker(250 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case src.tun.Outbound <- pkt:
		case <-deadline:
			t.Fatalf("%s -> %s: timed out sending", src.node.Name, dst.node.Name)
		}
	wait:
		for {
			select {
			case got := <-dst.recv:
				if bytes.Equal(got, pkt) {
					return
				}
				// A late retry from an earlier pair: keep waiting for ours.
			case <-retry.C: // first packets may be dropped while paths are found
				break wait
			case <-deadline:
				t.Fatalf("%s -> %s: timed out waiting for packet", src.node.Name, dst.node.Name)
			}
		}
	}
}

func waitPath(t *testing.T, n *testNode, peer *testNode, kind string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got := n.conn.Paths()[peer.node.Key].Kind; got == kind {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s -> %s: path %q, want %q", n.node.Name, peer.node.Name, n.conn.Paths()[peer.node.Key].Kind, kind)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestMeshDirect(t *testing.T) {
	a := newTestNode(t, "alpha", "100.64.0.1", magicsock.Options{})
	b := newTestNode(t, "bravo", "100.64.0.2", magicsock.Options{})
	c := newTestNode(t, "charlie", "100.64.0.3", magicsock.Options{})
	apply(t, a, b, c)
	if got := a.net.addrs; len(got) != 1 || got[0].String() != "100.64.0.1/10" {
		t.Fatalf("interface addresses = %v", got)
	}

	for _, pair := range [][2]*testNode{{a, b}, {b, c}, {c, a}, {b, a}} {
		sendPing(t, pair[0], pair[1], 20*time.Second)
		waitPath(t, pair[0], pair[1], "direct", 5*time.Second)
	}

	st, err := a.eng.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Name != "alpha" || len(st.Peers) != 2 || st.Peers[0].Name != "bravo" ||
		st.Peers[0].Path != "direct" || st.Peers[0].LastHandshake.IsZero() {
		t.Fatalf("status = %+v", st)
	}

	// Re-applying an identical netmap is a no-op and does not reset the address.
	apply(t, a, b, c)
	if len(a.net.addrs) != 1 {
		t.Fatalf("address set again: %v", a.net.addrs)
	}

	// Removing charlie from alpha's netmap removes the peer.
	if err := a.eng.Apply(meshNetmap(a, a, b)); err != nil {
		t.Fatal(err)
	}
	cfg, err := a.eng.dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg, c.node.Key.Hex()) {
		t.Fatal("charlie still configured on alpha")
	}
	if _, ok := a.conn.Paths()[c.node.Key]; ok {
		t.Fatal("charlie still known to magicsock")
	}
}

func TestRelayFallback(t *testing.T) {
	r := newRelay(t)
	opts := magicsock.Options{DisableLocalEndpoints: true}
	a := newTestNode(t, "alpha", "100.64.0.1", opts)
	b := newTestNode(t, "bravo", "100.64.0.2", opts)
	// Only unreachable endpoints are known: traffic must use the relay.
	dead := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:9")}
	a.node.Endpoints, b.node.Endpoints = dead, dead
	r.join(t, a)
	r.join(t, b)
	apply(t, a, b)

	sendPing(t, a, b, 15*time.Second)
	sendPing(t, b, a, 15*time.Second)
	waitPath(t, a, b, "relay", time.Second)
	st, err := a.eng.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Peers[0].Path != "relay" || st.Peers[0].LastHandshake.IsZero() {
		t.Fatalf("status = %+v", st.Peers[0])
	}
}

// TestUpgradeToDirect starts with no endpoints in the netmap: nodes learn
// their address from STUN, swap call-me-maybe through the relay, ping each
// other and move traffic off the relay.
func TestUpgradeToDirect(t *testing.T) {
	r := newRelay(t)
	stunPC, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = stun.Serve(ctx, stunPC, discard) }()
	stunAddr := stunPC.LocalAddr().(*net.UDPAddr).AddrPort()

	var mu sync.Mutex
	advertised := map[string][]netip.AddrPort{}
	mk := func(name, ip string) *testNode {
		return newTestNode(t, name, ip, magicsock.Options{
			DisableLocalEndpoints: true,
			OnEndpoints: func(eps []netip.AddrPort) {
				mu.Lock()
				advertised[name] = eps
				mu.Unlock()
			},
		})
	}
	a, b := mk("alpha", "100.64.0.1"), mk("bravo", "100.64.0.2")
	a.node.Endpoints, b.node.Endpoints = nil, nil
	for _, n := range []*testNode{a, b} {
		r.join(t, n)
		n.conn.SetSTUNServer(stunAddr)
	}
	apply(t, a, b)

	sendPing(t, a, b, 15*time.Second) // works right away through the relay
	waitPath(t, a, b, "direct", 30*time.Second)
	waitPath(t, b, a, "direct", 30*time.Second)
	sendPing(t, b, a, 5*time.Second)

	mu.Lock()
	defer mu.Unlock()
	want := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), a.eng.ListenPort())
	if got := advertised["alpha"]; len(got) != 1 || got[0] != want {
		t.Fatalf("alpha advertised %v, want [%v] from STUN", got, want)
	}
}

func TestParseStats(t *testing.T) {
	k1, _ := wgkey.NewPrivate()
	k2, _ := wgkey.NewPrivate()
	in := "private_key=00\nlisten_port=41641\n" +
		"public_key=" + k1.Public().Hex() + "\nendpoint=tp:abc\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\nrx_bytes=10\ntx_bytes=20\n" +
		"public_key=" + k2.Public().Hex() + "\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n"
	st, err := parseStats(in)
	if err != nil {
		t.Fatal(err)
	}
	p1 := st.peers[k1.Public()]
	if st.listenPort != 41641 || p1.rxBytes != 10 || p1.txBytes != 20 || !p1.lastHandshake.Equal(time.Unix(1700000000, 5)) {
		t.Fatalf("stats = %+v", st)
	}
	if p2, ok := st.peers[k2.Public()]; !ok || !p2.lastHandshake.IsZero() {
		t.Fatalf("peer 2 = %+v, %v", p2, ok)
	}
	if _, err := parseStats("listen_port=notanumber\n"); err == nil {
		t.Fatal("bad input accepted")
	}
}
