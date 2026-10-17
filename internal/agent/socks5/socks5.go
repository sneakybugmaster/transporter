// Package socks5 is a minimal SOCKS5 server (RFC 1928): CONNECT only, no
// authentication. In userspace mode it is how local programs reach the mesh;
// the dial function decides where connections go.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	version5 = 0x05

	methodNoAuth       = 0x00
	methodNoAcceptable = 0xff

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded          = 0x00
	repGeneralFailure     = 0x01
	repNetworkUnreachable = 0x03
	repHostUnreachable    = 0x04
	repConnRefused        = 0x05
	repCmdNotSupported    = 0x07
	repAddrNotSupported   = 0x08

	handshakeTimeout = 10 * time.Second
)

// DialFunc opens a connection to address ("host:port"), where host may be
// an IP address or a name.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Server serves SOCKS5 clients.
type Server struct {
	Dial DialFunc
	Log  *slog.Logger
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() { s.handle(ctx, c) })
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(handshakeTimeout))
	target, err := handshake(c)
	if err != nil {
		s.Log.Debug("socks5 handshake", "client", c.RemoteAddr(), "err", err)
		return
	}

	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	up, err := s.Dial(dctx, "tcp", target)
	cancel()
	if err != nil {
		s.Log.Debug("socks5 dial", "target", target, "err", err)
		_ = reply(c, replyCode(err), nil)
		return
	}
	defer up.Close()
	var bound netip.AddrPort
	if ta, ok := up.LocalAddr().(*net.TCPAddr); ok {
		bound = ta.AddrPort()
	}
	if err := reply(c, repSucceeded, &bound); err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{})

	// Copy in both directions until either side closes.
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(up, c)
	go pipe(c, up)
	select {
	case <-done:
		// Give the other direction a moment to drain after a half-close.
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	case <-ctx.Done():
	}
}

// handshake negotiates "no authentication" and reads a CONNECT request,
// returning the target as host:port.
func handshake(rw io.ReadWriter) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(rw, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != version5 {
		return "", fmt.Errorf("unsupported SOCKS version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(rw, methods); err != nil {
		return "", err
	}
	method := byte(methodNoAcceptable)
	for _, m := range methods {
		if m == methodNoAuth {
			method = methodNoAuth
		}
	}
	if _, err := rw.Write([]byte{version5, method}); err != nil {
		return "", err
	}
	if method == methodNoAcceptable {
		return "", errors.New("client offers no supported auth method")
	}

	var req [4]byte
	if _, err := io.ReadFull(rw, req[:]); err != nil {
		return "", err
	}
	if req[0] != version5 {
		return "", errors.New("bad request version")
	}
	if req[1] != cmdConnect {
		_ = reply(rw, repCmdNotSupported, nil)
		return "", fmt.Errorf("unsupported command %d", req[1])
	}
	var host string
	switch req[3] {
	case atypIPv4, atypIPv6:
		n := 4
		if req[3] == atypIPv6 {
			n = 16
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(rw, b); err != nil {
			return "", err
		}
		ip, _ := netip.AddrFromSlice(b)
		host = ip.String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(rw, l[:]); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(rw, b); err != nil {
			return "", err
		}
		host = string(b)
	default:
		_ = reply(rw, repAddrNotSupported, nil)
		return "", fmt.Errorf("unsupported address type %d", req[3])
	}
	var port [2]byte
	if _, err := io.ReadFull(rw, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func reply(w io.Writer, code byte, bound *netip.AddrPort) error {
	b := []byte{version5, code, 0x00}
	if bound != nil && bound.Addr().Is6() && !bound.Addr().Is4In6() {
		ip := bound.Addr().As16()
		b = append(b, atypIPv6)
		b = append(b, ip[:]...)
	} else {
		ip := [4]byte{}
		if bound != nil && bound.IsValid() {
			ip = bound.Addr().Unmap().As4()
		}
		b = append(b, atypIPv4)
		b = append(b, ip[:]...)
	}
	var port uint16
	if bound != nil {
		port = bound.Port()
	}
	b = binary.BigEndian.AppendUint16(b, port)
	_, err := w.Write(b)
	return err
}

func replyCode(err error) byte {
	var ne net.Error
	switch {
	case errors.Is(err, ErrUnreachable):
		return repNetworkUnreachable
	case errors.As(err, &ne) && ne.Timeout():
		return repHostUnreachable
	case isRefused(err):
		return repConnRefused
	default:
		return repGeneralFailure
	}
}

// ErrUnreachable may be returned by a DialFunc for destinations it refuses
// to route; clients see "network unreachable".
var ErrUnreachable = errors.New("destination not reachable through this proxy")

// isRefused recognises "connection refused" from the OS stack (Unix and
// Windows report it differently) and from gVisor's netstack.
func isRefused(err error) bool {
	return strings.Contains(err.Error(), "refused")
}
