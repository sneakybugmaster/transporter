package netcfg

import (
	"net"
	"net/netip"
	"slices"
)

// LocalEndpoints lists ip:port candidates on which peers may reach this host
// directly: global and private unicast addresses of up, non-loopback
// interfaces, IPv4 first. Interfaces named in skip (the mesh interface) and
// addresses inside the mesh prefix are left out.
func LocalEndpoints(port uint16, mesh netip.Prefix, skip ...string) ([]netip.AddrPort, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var v4, v6 []netip.AddrPort
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || slices.Contains(skip, ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !usable(ip) || (mesh.IsValid() && mesh.Contains(ip)) {
				continue
			}
			ap := netip.AddrPortFrom(ip, port)
			if ip.Is4() {
				v4 = append(v4, ap)
			} else {
				v6 = append(v6, ap)
			}
		}
	}
	return append(v4, v6...), nil
}

func usable(ip netip.Addr) bool {
	return ip.IsValid() && ip.IsGlobalUnicast() && !ip.IsLinkLocalUnicast()
}
