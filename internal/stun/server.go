package stun

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
)

// requests counts binding requests answered, for the coordinator's metrics.
var requests atomic.Uint64

// Requests returns the number of binding requests answered by Serve.
func Requests() uint64 { return requests.Load() }

// Serve answers binding requests on conn until ctx is cancelled.
func Serve(ctx context.Context, conn net.PacketConn, log *slog.Logger) error {
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		tx, err := ParseRequest(buf[:n])
		if err != nil {
			continue
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		requests.Add(1)
		if _, err := conn.WriteTo(Response(tx, ua.AddrPort()), from); err != nil {
			log.Debug("stun reply", "to", from, "err", err)
		}
	}
}
