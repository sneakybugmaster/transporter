package filter

import (
	"net/netip"
	"testing"
)

func FuzzFilter(f *testing.F) {
	f.Add(ipv4(ProtoTCP, peerA, self, 5000, 22))
	f.Add(icmp(icmpEchoRequest, peerB, self, 1))
	f.Add([]byte{0x46, 0, 0, 20})
	f.Fuzz(func(t *testing.T, b []byte) {
		flt := New()
		flt.SetRules([]Rule{{Srcs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Dsts: []Dst{{Prefix: netip.PrefixFrom(self, 32), Ports: PortRange{22, 22}}}}})
		flt.Outbound(b)
		_ = flt.Inbound(b)
	})
}
