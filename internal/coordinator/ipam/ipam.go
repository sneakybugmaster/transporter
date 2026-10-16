// Package ipam allocates overlay addresses from the mesh prefix.
package ipam

import (
	"errors"
	"net/netip"
)

// ErrExhausted is returned when every usable address in the prefix is taken.
var ErrExhausted = errors.New("ipam: address space exhausted")

// Allocate returns the lowest free IPv4 address in prefix, skipping the
// network and broadcast addresses and anything for which used returns true.
func Allocate(prefix netip.Prefix, used func(netip.Addr) bool) (netip.Addr, error) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() {
		return netip.Addr{}, errors.New("ipam: only IPv4 prefixes are supported")
	}
	if prefix.Bits() > 30 {
		return netip.Addr{}, errors.New("ipam: prefix too small, need at least a /30")
	}
	broadcast := lastAddr(prefix)
	for a := prefix.Addr().Next(); a.IsValid() && a.Less(broadcast); a = a.Next() {
		if !used(a) {
			return a, nil
		}
	}
	return netip.Addr{}, ErrExhausted
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	hostBits := 32 - p.Bits()
	for i := 3; i >= 0 && hostBits > 0; i-- {
		n := min(hostBits, 8)
		b[i] |= byte(1<<n - 1)
		hostBits -= n
	}
	return netip.AddrFrom4(b)
}
