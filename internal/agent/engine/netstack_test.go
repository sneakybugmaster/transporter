package engine

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/sneakybugmaster/transporter/internal/agent/magicsock"
	"github.com/sneakybugmaster/transporter/internal/agent/socks5"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

type stackNode struct {
	eng  *Engine
	net  *netstack.Net
	node Node
}

func newStackNode(t *testing.T, name, ip string) *stackNode {
	t.Helper()
	key, err := wgkey.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr(ip)
	dev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	c := magicsock.New(magicsock.Options{PrivateKey: key, Log: discard})
	eng, err := New(Config{PrivateKey: key, TUN: dev, Conn: c, Log: discard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		eng.Close()
		c.Shutdown()
	})
	return &stackNode{eng: eng, net: tnet, node: Node{
		Name:      name,
		Key:       key.Public(),
		Addresses: []netip.Prefix{netip.PrefixFrom(addr, 32)},
		Endpoints: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), eng.ListenPort())},
		Online:    true,
	}}
}

// TestUserspaceTCP runs TCP over WireGuard between two in-process network
// stacks (userspace mode), directly and through the SOCKS5 proxy.
func TestUserspaceTCP(t *testing.T) {
	a := newStackNode(t, "alpha", "100.64.0.1")
	b := newStackNode(t, "bravo", "100.64.0.2")
	for _, n := range []*stackNode{a, b} {
		peer := b
		if n == b {
			peer = a
		}
		if err := n.eng.Apply(Netmap{Self: n.node, Prefix: prefix, Peers: []Node{peer.node}}); err != nil {
			t.Fatal(err)
		}
	}

	// Echo server on bravo's mesh address, inside bravo's stack.
	ln, err := b.net.ListenTCPAddrPort(netip.MustParseAddrPort("100.64.0.2:7000"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()

	echo := func(c net.Conn, msg string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write([]byte(msg + "\n")); err != nil {
			t.Fatal(err)
		}
		got, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || got != msg+"\n" {
			t.Fatalf("echo = %q, %v", got, err)
		}
	}

	// Direct dial from alpha's stack (the first SYN may race the handshake).
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var c net.Conn
	for {
		dctx, dcancel := context.WithTimeout(ctx, 3*time.Second)
		c, err = a.net.DialContext(dctx, "tcp", "100.64.0.2:7000")
		dcancel()
		if err == nil || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("dial through mesh: %v", err)
	}
	echo(c, "hello over userspace wireguard")
	c.Close()

	// The same through alpha's SOCKS5 proxy, addressing bravo by name.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &socks5.Server{Log: discard, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		if host == "bravo" {
			host = "100.64.0.2"
		}
		return a.net.DialContext(ctx, network, net.JoinHostPort(host, port))
	}}
	go func() { _ = srv.Serve(ctx, proxyLn) }()

	pc, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = pc.Write([]byte{5, 1, 0})
	var m [2]byte
	_, _ = io.ReadFull(pc, m[:])
	req := append([]byte{5, 1, 0, 3, 5}, "bravo"...)
	req = binary.BigEndian.AppendUint16(req, 7000)
	_, _ = pc.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(pc, rep[:]); err != nil || rep[1] != 0 {
		t.Fatalf("socks reply %v, %v", rep, err)
	}
	echo(pc, "hello through socks5")
}
