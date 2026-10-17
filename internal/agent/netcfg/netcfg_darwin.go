//go:build darwin

package netcfg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Interface is a configured utun interface.
type Interface struct {
	TUN  tun.Device
	name string
	addr netip.Prefix

	mu       sync.Mutex
	routes   []netip.Prefix
	dnsFiles []string
}

// Create creates a utun interface (macOS picks the number; the requested
// name is ignored). It requires root.
func Create(string) (*Interface, error) {
	dev, err := tun.CreateTUN("utun", MTU)
	if err != nil {
		return nil, fmt.Errorf("create utun interface (needs root): %w", err)
	}
	name, err := dev.Name()
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	return &Interface{TUN: dev, name: name}, nil
}

// Name returns the interface name, e.g. utun5.
func (i *Interface) Name() string { return i.name }

// SetAddress assigns addr to the point-to-point utun interface and routes
// the whole mesh prefix through it.
func (i *Interface) SetAddress(addr netip.Prefix) error {
	ip := addr.Addr().String()
	if i.addr.IsValid() && i.addr != addr {
		_ = run("route", "-q", "-n", "delete", "-inet", i.addr.Masked().String(), "-interface", i.name)
		_ = run("ifconfig", i.name, "inet", i.addr.Addr().String(), "delete")
	}
	mask := net.IP(net.CIDRMask(addr.Bits(), 32)).String()
	if err := run("ifconfig", i.name, "inet", ip, ip, "netmask", mask, "mtu", fmt.Sprint(MTU), "up"); err != nil {
		return err
	}
	prefix := addr.Masked().String()
	if err := run("route", "-q", "-n", "add", "-inet", prefix, "-interface", i.name); err != nil {
		// Already present (e.g. after a restart): point it at this interface.
		if err := run("route", "-q", "-n", "change", "-inet", prefix, "-interface", i.name); err != nil {
			return err
		}
	}
	i.addr = addr
	return nil
}

func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // fixed ifconfig/route invocations
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
