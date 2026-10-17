//go:build darwin

package netcfg

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
)

const (
	resolverDir    = "/etc/resolver"
	resolverMarker = "# Added by Transporter; removed when it stops.\n"
)

// SetRoutes routes subnet routes into the utun interface. Using an exit
// node is not supported in TUN mode on macOS yet.
func (i *Interface) SetRoutes(routes []netip.Prefix) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if slices.ContainsFunc(routes, isDefault) {
		return fmt.Errorf("using an exit node: %w (use --userspace)", ErrUnsupported)
	}
	for _, r := range i.routes {
		if !slices.Contains(routes, r) {
			_ = run("route", "-q", "-n", "delete", "-inet", r.String(), "-interface", i.name)
		}
	}
	for _, r := range routes {
		if slices.Contains(i.routes, r) {
			continue
		}
		if err := run("route", "-q", "-n", "add", "-inet", r.String(), "-interface", i.name); err != nil {
			if err := run("route", "-q", "-n", "change", "-inet", r.String(), "-interface", i.name); err != nil {
				return err
			}
		}
	}
	i.routes = slices.Clone(routes)
	return nil
}

func isDefault(p netip.Prefix) bool { return p.Bits() == 0 }

// EnableForwarding is not supported on macOS yet.
func (i *Interface) EnableForwarding(netip.Prefix) error {
	return fmt.Errorf("advertising routes: %w", ErrUnsupported)
}

// SetDNS sends queries for domains to server with one /etc/resolver file per
// domain, which macOS uses for those domains only.
func (i *Interface) SetDNS(server netip.Addr, domains []string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	content := []byte(resolverMarker + "nameserver " + server.String() + "\n")
	var errs []error
	if len(domains) > 0 {
		if err := os.MkdirAll(resolverDir, 0o755); err != nil { //nolint:gosec // standard permissions for /etc/resolver
			return err
		}
	}
	var written []string
	for _, d := range domains {
		path := filepath.Join(resolverDir, d)
		if old, err := os.ReadFile(path); err == nil && !bytes.HasPrefix(old, []byte(resolverMarker)) { //nolint:gosec // validated domain under /etc/resolver
			errs = append(errs, fmt.Errorf("%s exists and was not written by Transporter; leaving it alone", path))
			continue
		}
		if err := os.WriteFile(path, content, 0o644); err != nil { //nolint:gosec // resolver files must be world-readable
			errs = append(errs, err)
			continue
		}
		written = append(written, path)
	}
	for _, old := range i.dnsFiles {
		if !slices.Contains(written, old) {
			removeResolverFile(old)
		}
	}
	i.dnsFiles = written
	return errors.Join(errs...)
}

func removeResolverFile(path string) {
	if b, err := os.ReadFile(path); err == nil && bytes.HasPrefix(b, []byte(resolverMarker)) { //nolint:gosec // our own resolver file
		_ = os.Remove(path)
	}
}

// Cleanup removes the resolver files; routes vanish with the interface.
func (i *Interface) Cleanup() {
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, f := range i.dnsFiles {
		removeResolverFile(f)
	}
	i.dnsFiles = nil
}
