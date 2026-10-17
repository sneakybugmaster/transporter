package tundev

import (
	"net/netip"
	"testing"
)

func FuzzDNSQuery(f *testing.F) {
	addr := netip.MustParseAddr("100.100.100.100")
	f.Add(udpPacket(netip.MustParseAddrPort("100.64.0.1:5353"), netip.AddrPortFrom(addr, 53), []byte("q"), 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		q, src, ok := dnsQuery(b, addr)
		if !ok {
			return
		}
		// Rebuilding a packet from what was parsed yields the same query.
		q2, src2, ok := dnsQuery(udpPacket(src, netip.AddrPortFrom(addr, 53), q, 0), addr)
		if !ok || src2 != src || string(q2) != string(q) {
			t.Fatalf("round trip changed the query")
		}
	})
}
