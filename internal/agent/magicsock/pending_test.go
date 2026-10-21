package magicsock

import (
	"bytes"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

// openPair opens two Conns on loopback whose keys are ordered low < high.
func openPair(t *testing.T) (low, high *Conn, lowRecv, highRecv conn.ReceiveFunc) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	var keys [2]wgkey.Key
	for i := range keys {
		k, err := wgkey.NewPrivate()
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = k
	}
	if pa, pb := keys[0].Public(), keys[1].Public(); bytes.Compare(pa[:], pb[:]) > 0 {
		keys[0], keys[1] = keys[1], keys[0]
	}
	var conns [2]*Conn
	var recvs [2]conn.ReceiveFunc
	for i, k := range keys {
		c := New(Options{PrivateKey: k, Log: log, DisableLocalEndpoints: true})
		fns, _, err := c.Open(0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		conns[i], recvs[i] = c, fns[0] // fns[0] receives UDP
	}
	return conns[0], conns[1], recvs[0], recvs[1]
}

func addrOf(c *Conn) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), c.LocalPort())
}

// recvOne reads packets from fn until one that is not disco arrives.
func recvOne(t *testing.T, fn conn.ReceiveFunc) []byte {
	t.Helper()
	got := make(chan []byte, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		eps := make([]conn.Endpoint, 1)
		n, err := fn(bufs, sizes, eps)
		if err == nil && n == 1 {
			got <- bufs[0][:sizes[0]]
		}
	}()
	select {
	case b := <-got:
		return b
	case <-time.After(15 * time.Second):
		t.Fatal("no packet received")
		return nil
	}
}

func TestPacketsWaitForAPath(t *testing.T) {
	low, high, lowRecv, highRecv := openPair(t)
	lowKey, highKey := low.pub, high.pub
	// The receive loop also processes disco replies; keep low's running.
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := []int{0}
		eps := make([]conn.Endpoint, 1)
		for {
			if _, err := lowRecv(bufs, sizes, eps); err != nil {
				return
			}
		}
	}()

	// Both know each other but no endpoints yet: there is no path.
	low.SetPeers([]PeerConfig{{Key: highKey, Name: "high"}})
	high.SetPeers([]PeerConfig{{Key: lowKey, Name: "low"}})

	ep, err := low.ParseEndpoint(EndpointString(highKey))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("handshake initiation")
	if err := low.Send([][]byte{msg}, ep); err != nil {
		t.Fatal(err)
	}

	// The higher-key side must not hold packets (see Send).
	hep, _ := high.ParseEndpoint(EndpointString(lowKey))
	if err := high.Send([][]byte{[]byte("dropped")}, hep); err != nil {
		t.Fatal(err)
	}
	high.mu.Lock()
	if n := len(high.peers[lowKey].pending); n != 0 {
		t.Errorf("higher-key side queued %d packets", n)
	}
	high.mu.Unlock()

	// Endpoints arrive; discovery finds the direct path and the held
	// packet is delivered.
	low.SetPeers([]PeerConfig{{Key: highKey, Name: "high", Endpoints: []netip.AddrPort{addrOf(high)}}})
	high.SetPeers([]PeerConfig{{Key: lowKey, Name: "low", Endpoints: []netip.AddrPort{addrOf(low)}}})
	if got := recvOne(t, highRecv); !bytes.Equal(got, msg) {
		t.Fatalf("received %q, want %q", got, msg)
	}
}

func TestPublicPortsFollowReflexiveAddress(t *testing.T) {
	c := New(Options{
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		ExtraEndpoints: []netip.AddrPort{netip.MustParseAddrPort("198.51.100.1:5000")},
		PublicPorts:    []uint16{41651},
	})
	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.advertisedLocked(); len(got) != 1 {
		t.Fatalf("before STUN: %v, want only the fixed endpoint", got)
	}
	for _, ip := range []string{"203.0.113.7", "203.0.113.99"} { // the public IP changes
		c.reflexive = netip.MustParseAddrPort(ip + ":61234")
		want := []netip.AddrPort{
			netip.MustParseAddrPort("198.51.100.1:5000"),
			netip.MustParseAddrPort(ip + ":41651"),
			c.reflexive,
		}
		if got := c.advertisedLocked(); !slices.Equal(got, want) {
			t.Fatalf("advertised %v, want %v", got, want)
		}
	}
}
