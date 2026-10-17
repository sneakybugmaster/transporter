//go:build windows

package netcfg

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// SetRoutes routes subnet routes into the Wintun adapter. Using an exit
// node is not supported in TUN mode on Windows yet.
func (i *Interface) SetRoutes(routes []netip.Prefix) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if slices.ContainsFunc(routes, isDefault) {
		return fmt.Errorf("using an exit node: %w (use --userspace)", ErrUnsupported)
	}
	unspec := netip.IPv4Unspecified()
	for _, r := range i.routes {
		if !slices.Contains(routes, r) {
			_ = i.luid.DeleteRoute(r, unspec)
		}
	}
	for _, r := range routes {
		if slices.Contains(i.routes, r) {
			continue
		}
		if err := i.luid.AddRoute(r, unspec, 0); err != nil {
			return fmt.Errorf("add route %s: %w", r, err)
		}
	}
	i.routes = slices.Clone(routes)
	return nil
}

func isDefault(p netip.Prefix) bool { return p.Bits() == 0 }

// EnableForwarding is not supported on Windows yet.
func (i *Interface) EnableForwarding(netip.Prefix) error {
	return fmt.Errorf("advertising routes: %w", ErrUnsupported)
}

const nrptComment = "Transporter"

// SetDNS sends queries for domains to server with Name Resolution Policy
// Table rules, which Windows applies to those domains only.
func (i *Interface) SetDNS(server netip.Addr, domains []string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	script := "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + nrptComment + "' } | Remove-DnsClientNrptRule -Force;"
	for _, d := range domains {
		script += fmt.Sprintf(" Add-DnsClientNrptRule -Namespace '.%s' -NameServers '%s' -Comment '%s' | Out-Null;", d, server, nrptComment)
	}
	if err := powershell(script); err != nil {
		return fmt.Errorf("%w: %w", ErrDNSUnsupported, err)
	}
	i.dnsSet = len(domains) > 0
	return nil
}

func powershell(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput() //nolint:gosec // domains are validated DNS names
	if err != nil {
		return fmt.Errorf("powershell: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Cleanup removes the NRPT rules; routes vanish with the adapter.
func (i *Interface) Cleanup() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.dnsSet {
		_ = powershell("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '" + nrptComment + "' } | Remove-DnsClientNrptRule -Force")
		i.dnsSet = false
	}
}
