// Package netcfg creates the TUN device and configures it at the OS level.
package netcfg

import "errors"

// ErrDNSUnsupported means the OS's resolver cannot be pointed at MagicDNS
// automatically; names still resolve when queried at the address directly.
var ErrDNSUnsupported = errors.New("cannot configure the system resolver")

// ErrUnsupported is returned for features this OS does not support in TUN
// mode.
var ErrUnsupported = errors.New("not supported on this OS")

// MTU leaves room for WireGuard overhead on links with an MTU as low as 1360,
// which covers PPPoE, most tunnels and IPv6 paths.
const MTU = 1280
