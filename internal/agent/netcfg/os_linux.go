//go:build linux

package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/sneakybugmaster/transporter/internal/netns"
)

// Policy routing: routes into the mesh (subnet routes, an exit node's
// default route) live in their own table. Rules send the agent's own marked
// sockets through the main table, let the main table answer for anything
// more specific than a default route (so the LAN stays reachable), and then
// consult the mesh table.
const (
	routeTable      = 52
	prioBypassMark  = 5210
	prioMainNoDflt  = 5230
	prioMeshTable   = 5270
	mainTable       = unix.RT_TABLE_MAIN
	ipForwardSysctl = "/proc/sys/net/ipv4/ip_forward"
)

func (i *Interface) policyRules() []*netlink.Rule {
	bypass := netlink.NewRule()
	bypass.Priority = prioBypassMark
	bypass.Mark = netns.Mark
	mask := uint32(netns.MarkMask)
	bypass.Mask = &mask
	bypass.Table = mainTable
	bypass.Family = unix.AF_INET

	mainNoDefault := netlink.NewRule()
	mainNoDefault.Priority = prioMainNoDflt
	mainNoDefault.Table = mainTable
	mainNoDefault.SuppressPrefixlen = 0
	mainNoDefault.Family = unix.AF_INET

	mesh := netlink.NewRule()
	mesh.Priority = prioMeshTable
	mesh.Table = routeTable
	mesh.Family = unix.AF_INET
	return []*netlink.Rule{bypass, mainNoDefault, mesh}
}

// SetRoutes makes the OS send traffic for routes (outside the mesh prefix)
// into the interface. A 0.0.0.0/0 route makes this node use an exit node.
func (i *Interface) SetRoutes(routes []netip.Prefix) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	link, err := netlink.LinkByName(i.name)
	if err != nil {
		return err
	}
	existing, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: routeTable}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("list routes: %w", err)
	}
	want := map[netip.Prefix]bool{}
	for _, r := range routes {
		want[r.Masked()] = true
	}
	for _, r := range existing {
		dst := netip.MustParsePrefix("0.0.0.0/0")
		if r.Dst != nil {
			if p, ok := prefixFromIPNet(r.Dst); ok {
				dst = p
			}
		}
		if want[dst] && r.LinkIndex == link.Attrs().Index {
			delete(want, dst)
			continue
		}
		if err := netlink.RouteDel(&r); err != nil && !errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("remove route %s: %w", dst, err)
		}
	}
	for p := range want {
		r := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), 32)},
			Table:     routeTable,
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteReplace(r); err != nil {
			return fmt.Errorf("add route %s: %w", p, err)
		}
	}
	if len(routes) > 0 && !i.rules {
		for _, r := range i.policyRules() {
			_ = netlink.RuleDel(r) // stale from a crash
			if err := netlink.RuleAdd(r); err != nil {
				return fmt.Errorf("add routing rule (priority %d): %w", r.Priority, err)
			}
		}
		i.rules = true
	} else if len(routes) == 0 && i.rules {
		i.delRulesLocked()
	}
	return nil
}

func (i *Interface) delRulesLocked() {
	for _, r := range i.policyRules() {
		_ = netlink.RuleDel(r)
	}
	i.rules = false
}

func prefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) {
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	bits, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), bits), true
}

// EnableForwarding lets this node forward mesh traffic to its subnets (and
// the internet, for an exit node): IPv4 forwarding on, and traffic from the
// mesh masqueraded behind this host's addresses, so the destination network
// needs no route back to the mesh.
func (i *Interface) EnableForwarding(meshPrefix netip.Prefix) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(i.forward) > 0 {
		return nil
	}
	if b, err := os.ReadFile(ipForwardSysctl); err != nil || strings.TrimSpace(string(b)) != "1" {
		if err := os.WriteFile(ipForwardSysctl, []byte("1\n"), 0o644); err != nil { //nolint:gosec // sysctl files are world-readable
			return fmt.Errorf("enable IP forwarding (in a container, start it with --sysctl net.ipv4.ip_forward=1): %w", err)
		}
	}
	src := meshPrefix.Masked().String()
	rules := [][]string{
		{"-t", "nat", "POSTROUTING", "-s", src, "!", "-o", i.name, "-j", "MASQUERADE"},
		// Hosts running Docker default FORWARD to DROP.
		{"-t", "filter", "FORWARD", "-i", i.name, "-j", "ACCEPT"},
		{"-t", "filter", "FORWARD", "-o", i.name, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}
	for _, r := range rules {
		args := slices.Insert(slices.Clone(r), 2, "-C")
		if iptables(args...) == nil {
			continue // already present (e.g. after a crash)
		}
		op := "-A"
		if r[1] == "filter" {
			op = "-I"
		}
		if err := iptables(slices.Insert(slices.Clone(r), 2, op)...); err != nil {
			i.delForwardLocked()
			return fmt.Errorf("subnet routing needs iptables: %w", err)
		}
		i.forward = append(i.forward, r)
	}
	return nil
}

func (i *Interface) delForwardLocked() {
	for _, r := range i.forward {
		_ = iptables(slices.Insert(slices.Clone(r), 2, "-D")...)
	}
	i.forward = nil
}

func iptables(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "iptables", append([]string{"-w"}, args...)...).CombinedOutput() //nolint:gosec // fixed rule templates
	if err != nil {
		return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetDNS sends queries for domains to server, through systemd-resolved's
// per-link DNS. The first domain is also a search domain, so bare node
// names resolve. An empty list removes the configuration.
func (i *Interface) SetDNS(server netip.Addr, domains []string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if len(domains) == 0 {
		if i.dnsSet {
			_ = resolvectl("revert", i.name)
			i.dnsSet = false
		}
		return nil
	}
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return fmt.Errorf("%w: resolvectl (systemd-resolved) not found", ErrDNSUnsupported)
	}
	if err := resolvectl("dns", i.name, server.String()); err != nil {
		return fmt.Errorf("%w: %w", ErrDNSUnsupported, err)
	}
	args := []string{"domain", i.name, domains[0]}
	for _, d := range domains[1:] {
		args = append(args, "~"+d)
	}
	if err := resolvectl(args...); err != nil {
		return err
	}
	i.dnsSet = true
	return nil
}

func resolvectl(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "resolvectl", args...).CombinedOutput() //nolint:gosec // interface name and validated domains
	if err != nil {
		return fmt.Errorf("resolvectl %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Cleanup undoes OS changes that do not disappear with the interface:
// routing rules, forwarding rules and DNS settings.
func (i *Interface) Cleanup() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.rules {
		i.delRulesLocked()
	}
	i.delForwardLocked()
	if i.dnsSet {
		_ = resolvectl("revert", i.name)
		i.dnsSet = false
	}
}
