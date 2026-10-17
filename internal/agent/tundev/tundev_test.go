package tundev

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/sneakybugmaster/transporter/internal/filter"
)

// fakeTUN hands out queued packets on Read and records Writes.
type fakeTUN struct {
	in      chan []byte
	mu      sync.Mutex
	written [][]byte
	wrote   chan struct{}
}

func newFake() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 8), wrote: make(chan struct{}, 8)}
}

func (f *fakeTUN) File() *os.File           { return nil }
func (f *fakeTUN) MTU() (int, error)        { return 1280, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return nil }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return 4 }

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for n < len(bufs) {
		select {
		case p := <-f.in:
			sizes[n] = copy(bufs[n][offset:], p)
			n++
		default:
			return n, nil
		}
	}
	return n, nil
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	f.mu.Unlock()
	f.wrote <- struct{}{}
	return len(bufs), nil
}

var (
	self = netip.MustParseAddr("100.64.0.1")
	peer = netip.MustParseAddr("100.64.0.2")
	dns  = netip.MustParseAddr("100.100.100.100")
)

func tcp(src, dst netip.Addr, sport, dport uint16) []byte {
	b := udpPacket(netip.AddrPortFrom(src, sport), netip.AddrPortFrom(dst, dport), []byte("x"), 0)
	b[9] = filter.ProtoTCP
	return b
}

func readAll(t *testing.T, d *Device) []int {
	t.Helper()
	bufs := make([][]byte, 4)
	for i := range bufs {
		bufs[i] = make([]byte, 2000)
	}
	sizes := make([]int, 4)
	n, err := d.Read(bufs, sizes, 16)
	if err != nil {
		t.Fatal(err)
	}
	return sizes[:n]
}

func TestFilterBothWays(t *testing.T) {
	fake := newFake()
	f := filter.New()
	f.SetRules(nil)
	d := Wrap(context.Background(), fake, Options{Filter: f})

	// Outbound connection, then its reply and an unsolicited packet.
	fake.in <- tcp(self, peer, 40000, 443)
	if sizes := readAll(t, d); len(sizes) != 1 || sizes[0] == 0 {
		t.Fatalf("outbound packet not passed to WireGuard: %v", sizes)
	}
	reply := append(make([]byte, 16), tcp(peer, self, 443, 40000)...)
	stranger := append(make([]byte, 16), tcp(peer, self, 5555, 22)...)
	n, err := d.Write([][]byte{stranger, reply, stranger}, 16)
	if err != nil || n != 3 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if len(fake.written) != 1 || !bytes.Equal(fake.written[0], reply[16:]) {
		t.Fatalf("delivered %d packets, want only the reply", len(fake.written))
	}
	// Everything dropped: nothing reaches the OS, no error.
	if n, err := d.Write([][]byte{stranger}, 16); n != 1 || err != nil || len(fake.written) != 1 {
		t.Fatalf("Write of a dropped packet = %d, %v", n, err)
	}
}

func TestDNSIntercept(t *testing.T) {
	fake := newFake()
	f := filter.New()
	d := Wrap(context.Background(), fake, Options{
		Filter:  f,
		DNSAddr: dns,
		DNS: func(_ context.Context, q []byte) []byte {
			return append([]byte("answer:"), q...)
		},
	})
	client := netip.AddrPortFrom(self, 5353)
	fake.in <- udpPacket(client, netip.AddrPortFrom(dns, 53), []byte("query"), 0)
	fake.in <- udpPacket(client, netip.AddrPortFrom(peer, 53), []byte("not for us"), 0)
	sizes := readAll(t, d)
	if len(sizes) != 2 || sizes[0] != 0 || sizes[1] == 0 {
		t.Fatalf("sizes = %v, want the DNS query consumed and the other passed on", sizes)
	}
	select {
	case <-fake.wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("no DNS answer written")
	}
	resp := fake.written[0]
	if checksum(resp[:20], 0) != 0 {
		t.Fatal("bad IPv4 header checksum")
	}
	payload, src, ok := func() ([]byte, netip.AddrPort, bool) {
		// Parse it back as if it were a query to the client.
		return dnsQueryTo(resp, client)
	}()
	if !ok || src != netip.AddrPortFrom(dns, 53) || string(payload) != "answer:query" {
		t.Fatalf("answer = %q from %v (ok %v)", payload, src, ok)
	}
}

// dnsQueryTo extracts the UDP payload of a packet to dst.
func dnsQueryTo(b []byte, dst netip.AddrPort) ([]byte, netip.AddrPort, bool) {
	if netip.AddrFrom4([4]byte(b[16:20])) != dst.Addr() || binary.BigEndian.Uint16(b[22:24]) != dst.Port() {
		return nil, netip.AddrPort{}, false
	}
	src := netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[12:16])), binary.BigEndian.Uint16(b[20:22]))
	return b[28:], src, true
}
