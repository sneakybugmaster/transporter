// Package netcfg creates the TUN device and configures it at the OS level.
package netcfg

// MTU leaves room for WireGuard overhead on links with an MTU as low as 1360,
// which covers PPPoE, most tunnels and IPv6 paths.
const MTU = 1280
