package socks5

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"testing"
	"time"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// echoServer returns the address of a TCP server that echoes lines.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
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
	return ln.Addr().String()
}

func startProxy(t *testing.T, dial DialFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &Server{Dial: dial, Log: discard}
	go func() { _ = s.Serve(ctx, ln) }()
	return ln.Addr().String()
}

// connect performs a SOCKS5 CONNECT and returns the reply code.
func connect(t *testing.T, proxy string, domain string, port int) (net.Conn, byte) {
	t.Helper()
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m != [2]byte{5, 0} {
		t.Fatalf("method reply %v, %v", m, err)
	}
	req := []byte{5, 1, 0, 3, byte(len(domain))}
	req = append(req, domain...)
	req = binary.BigEndian.AppendUint16(req, uint16(port)) //nolint:gosec // test ports
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatal(err)
	}
	return c, rep[1]
}

func TestConnectAndRelay(t *testing.T) {
	echo := echoServer(t)
	_, port, _ := net.SplitHostPort(echo)
	var asked string
	proxy := startProxy(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		asked = addr
		// "peer" resolves to the echo server, like a mesh name would.
		return (&net.Dialer{}).DialContext(ctx, network, echo)
	})
	p, _ := strconv.Atoi(port)
	c, code := connect(t, proxy, "peer", p)
	defer c.Close()
	if code != repSucceeded {
		t.Fatalf("reply code %d", code)
	}
	if asked != "peer:"+port {
		t.Fatalf("dial asked for %q", asked)
	}
	if _, err := c.Write([]byte("hello mesh\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "hello mesh\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
}

func TestDialFailuresMapToReplyCodes(t *testing.T) {
	tests := []struct {
		err  error
		want byte
	}{
		{ErrUnreachable, repNetworkUnreachable},
		{&net.OpError{Op: "dial", Err: errors.New("connect: connection refused")}, repConnRefused},
		{errors.New("boom"), repGeneralFailure},
	}
	for _, tt := range tests {
		proxy := startProxy(t, func(context.Context, string, string) (net.Conn, error) { return nil, tt.err })
		c, code := connect(t, proxy, "x", 1)
		_ = c.Close()
		if code != tt.want {
			t.Errorf("%v: code %d, want %d", tt.err, code, tt.want)
		}
	}
}

func TestRejectsUnsupportedRequests(t *testing.T) {
	proxy := startProxy(t, func(context.Context, string, string) (net.Conn, error) {
		t.Error("dial should not be called")
		return nil, errors.New("no")
	})

	// Username/password only: no acceptable method.
	c, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte{5, 1, 2})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != methodNoAcceptable {
		t.Fatalf("method reply %v, %v", m, err)
	}
	_ = c.Close()

	// BIND command.
	c, err = net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{5, 1, 0})
	_, _ = io.ReadFull(c, m[:])
	_, _ = c.Write([]byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 80})
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil || rep[1] != repCmdNotSupported {
		t.Fatalf("bind reply %v, %v", rep, err)
	}
}
