package agent

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// meshNetwork is how the agent itself talks to the mesh: through the OS
// network stack in TUN mode, or through its own gVisor stack in userspace
// mode, where the OS knows nothing about mesh addresses.
type meshNetwork interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	ListenUDP(ctx context.Context, addr netip.AddrPort) (net.PacketConn, error)
}

type osNetwork struct{}

func (osNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (osNetwork) ListenUDP(ctx context.Context, addr netip.AddrPort) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, "udp", addr.String())
}

type stackNetwork struct{ n *netstack.Net }

func (s stackNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return s.n.DialContext(ctx, network, address)
}

func (s stackNetwork) ListenUDP(_ context.Context, addr netip.AddrPort) (net.PacketConn, error) {
	return s.n.ListenUDPAddrPort(addr)
}

// userspaceNet stands in for interface configuration in userspace mode: the
// address is fixed when the stack is created.
type userspaceNet struct{ addr netip.Addr }

func (u userspaceNet) SetAddress(p netip.Prefix) error {
	if p.Addr() != u.addr {
		return fmt.Errorf("mesh address changed from %s to %s: restart the agent", u.addr, p.Addr())
	}
	return nil
}
