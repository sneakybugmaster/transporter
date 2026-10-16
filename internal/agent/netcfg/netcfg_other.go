//go:build !linux

package netcfg

import (
	"errors"
	"net/netip"
	"runtime"

	"golang.zx2c4.com/wireguard/tun"
)

// Interface is a configured TUN interface.
type Interface struct {
	TUN tun.Device
}

// Create is not implemented on this platform yet (planned for Phase 4).
func Create(string) (*Interface, error) {
	return nil, errors.New("the agent does not support " + runtime.GOOS + " yet; Linux only for now")
}

// Name returns the interface name.
func (i *Interface) Name() string { return "" }

// SetAddress is not implemented on this platform.
func (i *Interface) SetAddress(netip.Prefix) error {
	return errors.New("not supported on " + runtime.GOOS)
}
