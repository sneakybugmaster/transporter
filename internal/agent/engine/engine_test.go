package engine

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/tuntest"

	"github.com/sneakybugmaster/transporter/internal/agent/wgkey"
)

var prefix = netip.MustParsePrefix("100.64.0.0/10")

type testNode struct {
	eng  *Engine
	tun  *tuntest.ChannelTUN
	node Node
	net  *fakeNet
}

type fakeNet struct{ addrs []netip.Prefix }

func (f *fakeNet) SetAddress(p netip.Prefix) error {
	f.addrs = append(f.addrs, p)
	return nil
}

func newTestNode(t *testing.T, name string, ip string) *testNode {
	t.Helper()
	key, err := wgkey.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	ct := tuntest.NewChannelTUN()
	fn := &fakeNet{}
	eng, err := New(Config{
		PrivateKey: key,
		TUN:        ct.TUN(),
		Net:        fn,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	port := eng.ListenPort()
	if port == 0 {
		t.Fatal("listen port is 0")
	}
	return &testNode{
		eng: eng,
		tun: ct,
		net: fn,
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

// sendPing injects an ICMP echo at src's TUN and waits for it at dst's TUN.
func sendPing(t *testing.T, src, dst *testNode, timeout time.Duration) {
	t.Helper()
	pkt := tuntest.Ping(dst.node.Addresses[0].Addr(), src.node.Addresses[0].Addr())
	deadline := time.After(timeout)
	retry := time.NewTicker(500 * time.Millisecond)
	defer retry.Stop()
	for {
		select {
		case src.tun.Outbound <- pkt:
		case <-deadline:
			t.Fatalf("%s -> %s: timed out sending", src.node.Name, dst.node.Name)
		}
		select {
		case got := <-dst.tun.Inbound:
			if !bytes.Equal(got, pkt) {
				t.Fatalf("%s -> %s: packet mismatch", src.node.Name, dst.node.Name)
			}
			return
		case <-retry.C: // first packets may be dropped while handshaking
		case <-deadline:
			t.Fatalf("%s -> %s: timed out waiting for packet", src.node.Name, dst.node.Name)
		}
	}
}

func TestMeshForwardsPackets(t *testing.T) {
	a := newTestNode(t, "alpha", "100.64.0.1")
	b := newTestNode(t, "bravo", "100.64.0.2")
	c := newTestNode(t, "charlie", "100.64.0.3")
	all := []*testNode{a, b, c}
	for _, n := range all {
		if err := n.eng.Apply(meshNetmap(n, all...)); err != nil {
			t.Fatal(err)
		}
	}
	if got := a.net.addrs; len(got) != 1 || got[0].String() != "100.64.0.1/10" {
		t.Fatalf("interface addresses = %v", got)
	}

	for _, pair := range [][2]*testNode{{a, b}, {b, c}, {c, a}, {b, a}} {
		sendPing(t, pair[0], pair[1], 10*time.Second)
	}

	st, err := a.eng.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Name != "alpha" || len(st.Peers) != 2 || st.Peers[0].Name != "bravo" || st.Peers[0].LastHandshake.IsZero() {
		t.Fatalf("status = %+v", st)
	}

	// Re-applying an identical netmap is a no-op and does not reset the address.
	if err := a.eng.Apply(meshNetmap(a, all...)); err != nil {
		t.Fatal(err)
	}
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
}

func TestEndpointRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for WireGuard handshake retries")
	}
	a := newTestNode(t, "alpha", "100.64.0.1")
	b := newTestNode(t, "bravo", "100.64.0.2")

	// Alpha only knows a dead endpoint for bravo first, then the real one;
	// bravo knows no endpoint for alpha so it cannot initiate.
	dead := netip.MustParseAddrPort("127.0.0.1:9")
	bForA := b.node
	bForA.Endpoints = append([]netip.AddrPort{dead}, b.node.Endpoints...)
	aForB := a.node
	aForB.Endpoints = nil

	if err := a.eng.Apply(Netmap{Self: a.node, Prefix: prefix, Peers: []Node{bForA}}); err != nil {
		t.Fatal(err)
	}
	if err := b.eng.Apply(Netmap{Self: b.node, Prefix: prefix, Peers: []Node{aForB}}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.eng.Run(ctx)

	sendPing(t, a, b, 30*time.Second)
	st, err := a.eng.Status()
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Peers[0].Endpoint; got != b.node.Endpoints[0].String() {
		t.Fatalf("alpha uses endpoint %s for bravo, want %s", got, b.node.Endpoints[0])
	}
}

func TestParseStats(t *testing.T) {
	k1, _ := wgkey.NewPrivate()
	k2, _ := wgkey.NewPrivate()
	in := "private_key=00\nlisten_port=41641\n" +
		"public_key=" + k1.Public().Hex() + "\nendpoint=192.0.2.1:41641\nlast_handshake_time_sec=1700000000\nlast_handshake_time_nsec=5\nrx_bytes=10\ntx_bytes=20\n" +
		"public_key=" + k2.Public().Hex() + "\nlast_handshake_time_sec=0\nlast_handshake_time_nsec=0\n"
	st, err := parseStats(in)
	if err != nil {
		t.Fatal(err)
	}
	p1 := st.peers[k1.Public()]
	if st.listenPort != 41641 || p1.endpoint.String() != "192.0.2.1:41641" || p1.rxBytes != 10 || p1.txBytes != 20 ||
		!p1.lastHandshake.Equal(time.Unix(1700000000, 5)) {
		t.Fatalf("stats = %+v", st)
	}
	if p2, ok := st.peers[k2.Public()]; !ok || !p2.lastHandshake.IsZero() {
		t.Fatalf("peer 2 = %+v, %v", p2, ok)
	}
	if _, err := parseStats("listen_port=notanumber\n"); err == nil {
		t.Fatal("bad input accepted")
	}
}
