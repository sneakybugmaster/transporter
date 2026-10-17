//go:build windows

package netcfg

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Interface is a configured Wintun adapter.
type Interface struct {
	TUN  tun.Device
	name string
	luid winipcfg.LUID
}

// Create creates a Wintun adapter. It requires Administrator rights and
// wintun.dll next to transporter.exe (shipped in the Windows archives).
func Create(name string) (*Interface, error) {
	if name == "" {
		name = "Transporter"
	}
	dev, err := tun.CreateTUN(name, MTU)
	if err != nil {
		return nil, fmt.Errorf("create Wintun adapter %q (run as Administrator; wintun.dll must be next to transporter.exe): %w", name, err)
	}
	native, ok := dev.(*tun.NativeTun)
	if !ok {
		_ = dev.Close()
		return nil, errors.New("unexpected TUN implementation")
	}
	return &Interface{TUN: dev, name: name, luid: winipcfg.LUID(native.LUID())}, nil
}

// Name returns the adapter name.
func (i *Interface) Name() string { return i.name }

// SetAddress replaces the adapter's IPv4 addresses with addr; Windows adds
// the on-link route for the whole mesh prefix.
func (i *Interface) SetAddress(addr netip.Prefix) error {
	if err := i.luid.SetIPAddressesForFamily(winipcfg.AddressFamily(2 /* AF_INET */), []netip.Prefix{addr}); err != nil {
		return fmt.Errorf("set adapter address %s: %w", addr, err)
	}
	return nil
}
