//go:build windows

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Interface is a configured Wintun adapter.
type Interface struct {
	TUN  tun.Device
	name string
	luid winipcfg.LUID

	mu     sync.Mutex
	routes []netip.Prefix
	dnsSet bool
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
	i := &Interface{name: name, luid: winipcfg.LUID(native.LUID())}
	i.TUN = &firewalledTUN{Device: dev, rule: i.firewallRule()}
	deleteFirewallRule(i.firewallRule()) // left over from a crash
	return i, nil
}

// Name returns the adapter name.
func (i *Interface) Name() string { return i.name }

// SetAddress replaces the adapter's IPv4 addresses with addr; Windows adds
// the on-link route for the whole mesh prefix.
//
// Windows treats the adapter as an unidentified public network and its
// firewall drops unsolicited inbound traffic, so it also allows inbound
// traffic from the mesh to this address. Which peers may reach the node is
// decided by the mesh, not by the host firewall.
func (i *Interface) SetAddress(addr netip.Prefix) error {
	if err := i.luid.SetIPAddressesForFamily(winipcfg.AddressFamily(2 /* AF_INET */), []netip.Prefix{addr}); err != nil {
		return fmt.Errorf("set adapter address %s: %w", addr, err)
	}
	rule := i.firewallRule()
	deleteFirewallRule(rule)
	if err := netsh("advfirewall", "firewall", "add", "rule", "name="+rule, "dir=in", "action=allow",
		"protocol=any", "profile=any", "localip="+addr.Addr().String(), "remoteip="+addr.Masked().String()); err != nil {
		return fmt.Errorf("allow mesh traffic through Windows Firewall: %w", err)
	}
	return nil
}

func (i *Interface) firewallRule() string { return "Transporter mesh (" + i.name + ")" }

// firewalledTUN removes the adapter's firewall rule when it is closed.
type firewalledTUN struct {
	tun.Device
	rule string
}

func (t *firewalledTUN) Close() error {
	deleteFirewallRule(t.rule)
	return t.Device.Close()
}

func deleteFirewallRule(name string) {
	_ = netsh("advfirewall", "firewall", "delete", "rule", "name="+name) // fails when absent
}

func netsh(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "netsh", args...).CombinedOutput() //nolint:gosec // fixed netsh invocations
	if err != nil {
		return fmt.Errorf("netsh %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
