// Package pingsvc implements a tiny UDP echo protocol used by
// `transporter ping` to measure round trips through the mesh without needing
// raw sockets or root.
package pingsvc

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// Port is the UDP port the echo service listens on, on the mesh address only.
const Port = 41642

var magic = [4]byte{'T', 'P', 'N', 'G'}

const (
	typeRequest = 1
	typeReply   = 2
	packetLen   = 4 + 1 + 4 + 8 // magic, type, seq, send time
)

// Serve answers echo requests on pc until ctx is cancelled. pc is normally
// bound to the node's mesh address and Port.
func Serve(ctx context.Context, pc net.PacketConn) error {
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	buf := make([]byte, 64)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n != packetLen || [4]byte(buf[:4]) != magic || buf[4] != typeRequest {
			continue
		}
		buf[4] = typeReply
		_, _ = pc.WriteTo(buf[:n], from)
	}
}

// Result is the outcome of one probe.
type Result struct {
	Seq uint32
	RTT time.Duration
	Err error
}

// ErrTimeout is reported for probes without a reply.
var ErrTimeout = errors.New("timeout")

// Ping sends count probes over conn (a UDP connection to a peer's Port),
// one per interval, calling fn with each result as it completes.
func Ping(ctx context.Context, conn net.Conn, count int, interval, timeout time.Duration, fn func(Result)) error {
	buf := make([]byte, 64)
	for seq := uint32(1); seq <= uint32(count); seq++ { //nolint:gosec // count is small and positive
		if seq > 1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
		pkt := make([]byte, packetLen)
		copy(pkt, magic[:])
		pkt[4] = typeRequest
		binary.BigEndian.PutUint32(pkt[5:], seq)
		start := time.Now()
		binary.BigEndian.PutUint64(pkt[9:], uint64(start.UnixNano())) //nolint:gosec // timestamps are positive
		if _, err := conn.Write(pkt); err != nil {
			fn(Result{Seq: seq, Err: err})
			continue
		}
		fn(awaitReply(conn, buf, seq, start, timeout))
	}
	return nil
}

func awaitReply(conn net.Conn, buf []byte, seq uint32, start time.Time, timeout time.Duration) Result {
	deadline := start.Add(timeout)
	_ = conn.SetReadDeadline(deadline)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return Result{Seq: seq, Err: ErrTimeout}
			}
			return Result{Seq: seq, Err: err}
		}
		if n == packetLen && [4]byte(buf[:4]) == magic && buf[4] == typeReply && binary.BigEndian.Uint32(buf[5:]) == seq {
			return Result{Seq: seq, RTT: time.Since(start)}
		}
		// Late reply to an earlier probe: keep waiting for ours.
	}
}
