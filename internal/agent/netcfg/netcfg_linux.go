//go:build linux

package netcfg

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

// Interface is a configured TUN interface.
type Interface struct {
	TUN  tun.Device
	name string

	mu      sync.Mutex
	rules   bool       // policy routing rules installed
	forward [][]string // iptables rules added (without -A/-D)
	dnsSet  bool
}

// Create creates the TUN interface. It requires CAP_NET_ADMIN.
func Create(name string) (*Interface, error) {
	dev, err := tun.CreateTUN(name, MTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q (needs root or CAP_NET_ADMIN): %w", name, err)
	}
	if actual, err := dev.Name(); err == nil {
		name = actual
	}
	return &Interface{TUN: dev, name: name}, nil
}

// Name returns the interface name.
func (i *Interface) Name() string { return i.name }

// SetAddress assigns addr to the interface (replacing other IPv4 addresses)
// and brings it up. The prefix length makes the kernel route the whole mesh
// prefix through the interface.
func (i *Interface) SetAddress(addr netip.Prefix) error {
	link, err := netlink.LinkByName(i.name)
	if err != nil {
		return err
	}
	want := &netlink.Addr{IPNet: &net.IPNet{
		IP:   addr.Addr().AsSlice(),
		Mask: net.CIDRMask(addr.Bits(), 32),
	}}
	existing, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, a := range existing {
		if !a.IP.Equal(want.IP) || a.Mask.String() != want.Mask.String() {
			if err := netlink.AddrDel(link, &a); err != nil {
				return fmt.Errorf("remove old address %s: %w", a.IPNet, err)
			}
		}
	}
	if err := netlink.AddrReplace(link, want); err != nil {
		return fmt.Errorf("add address %s: %w", addr, err)
	}
	return netlink.LinkSetUp(link)
}
