package stun

import (
	"context"
	"log/slog"
	"net"
)

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
		if _, err := conn.WriteTo(Response(tx, ua.AddrPort()), from); err != nil {
			log.Debug("stun reply", "to", from, "err", err)
		}
	}
}
