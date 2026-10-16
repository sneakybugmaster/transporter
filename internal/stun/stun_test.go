package stun

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	for _, s := range []string{"203.0.113.7:41641", "[2001:db8::1]:3478"} {
		addr := netip.MustParseAddrPort(s)
		tx := NewTxID()

		req := Request(tx)
		if !Is(req) {
			t.Fatal("request not recognised")
		}
		gotTx, err := ParseRequest(req)
		if err != nil || gotTx != tx {
			t.Fatalf("ParseRequest = %v, %v", gotTx, err)
		}

		resp := Response(tx, addr)
		if !Is(resp) {
			t.Fatal("response not recognised")
		}
		gotTx, got, err := ParseResponse(resp)
		if err != nil || gotTx != tx || got != addr {
			t.Fatalf("ParseResponse = %v, %v, %v; want %v", gotTx, got, err, addr)
		}
	}
}

func TestIsRejectsOtherProtocols(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		{1, 0, 0, 0}, // WireGuard handshake initiation prefix
		make([]byte, 148),
		[]byte("TPDSC\x01 something that is long enough to look like a header"),
	} {
		if Is(b) {
			t.Errorf("Is(%q) = true", b)
		}
	}
	if _, _, err := ParseResponse(Request(NewTxID())); err == nil {
		t.Error("request parsed as response")
	}
}

func TestServer(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = Serve(ctx, srv, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tx := NewTxID()
	if _, err := c.WriteTo(Request(tx), srv.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	gotTx, addr, err := ParseResponse(buf[:n])
	if err != nil || gotTx != tx || addr != c.LocalAddr().(*net.UDPAddr).AddrPort() {
		t.Fatalf("got %v %v %v, want %v", gotTx, addr, err, c.LocalAddr())
	}
}

func FuzzParseResponse(f *testing.F) {
	f.Add(Response(NewTxID(), netip.MustParseAddrPort("192.0.2.1:1")))
	f.Add(Request(NewTxID()))
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _, _ = ParseResponse(b) // must not panic
		_, _ = ParseRequest(b)
	})
}
