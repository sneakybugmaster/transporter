//go:build !linux && !darwin && !windows

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

// Create is not implemented on this platform.
func Create(string) (*Interface, error) {
	return nil, errors.New("kernel TUN mode is not supported on " + runtime.GOOS + "; use --userspace")
}

// Name returns the interface name.
func (i *Interface) Name() string { return "" }

// SetAddress is not implemented on this platform.
func (i *Interface) SetAddress(netip.Prefix) error {
	return errors.New("not supported on " + runtime.GOOS)
}

// SetRoutes is not implemented on this platform.
func (i *Interface) SetRoutes([]netip.Prefix) error { return ErrUnsupported }

// EnableForwarding is not implemented on this platform.
func (i *Interface) EnableForwarding(netip.Prefix) error { return ErrUnsupported }

// SetDNS is not implemented on this platform.
func (i *Interface) SetDNS(netip.Addr, []string) error { return ErrDNSUnsupported }

// Cleanup does nothing on this platform.
func (i *Interface) Cleanup() {}
