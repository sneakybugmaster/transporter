// Package netns keeps the agent's own traffic (control plane, relay and
// WireGuard's UDP socket) out of the tunnel. On Linux its sockets carry
// Mark, which the policy routing rules installed for subnet routes and exit
// nodes send through the main routing table. Elsewhere it is a no-op.
package netns

import (
	"context"
	"net"
	"time"
)

// Mark is the firewall mark set on the agent's own sockets.
const Mark = 0x80000

// MarkMask selects the bits of Mark in routing rules.
const MarkMask = 0xff0000

// Dialer returns a dialer whose connections bypass the tunnel.
func Dialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: control, Resolver: resolver}
}

// ListenConfig returns a listen config whose sockets bypass the tunnel.
func ListenConfig() *net.ListenConfig { return &net.ListenConfig{Control: control} }

// Resolver looks names up without going through the tunnel.
func Resolver() *net.Resolver { return resolver }

// DialContext dials with Dialer.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return Dialer().DialContext(ctx, network, address)
}
