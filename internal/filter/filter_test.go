package filter

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

var (
	self  = netip.MustParseAddr("100.64.0.1")
	peerA = netip.MustParseAddr("100.64.0.2")
	peerB = netip.MustParseAddr("100.64.0.3")
)

// ipv4 builds a minimal IPv4 packet with a TCP/UDP or ICMP header.
func ipv4(proto uint8, src, dst netip.Addr, sport, dport uint16) []byte {
	b := make([]byte, 28)
	b[0] = 0x45
	b[9] = proto
	s, d := src.As4(), dst.As4()
	copy(b[12:16], s[:])
	copy(b[16:20], d[:])
	binary.BigEndian.PutUint16(b[20:22], sport)
	binary.BigEndian.PutUint16(b[22:24], dport)
	return b
}

func icmp(typ uint8, src, dst netip.Addr, id uint16) []byte {
	b := ipv4(ProtoICMP, src, dst, 0, 0)
	b[20] = typ
	b[21] = 0
	binary.BigEndian.PutUint16(b[24:26], id)
	return b
}

func rules() []Rule {
	return []Rule{{
		Srcs:   []netip.Prefix{netip.PrefixFrom(peerA, 32)},
		Dsts:   []Dst{{Prefix: netip.PrefixFrom(self, 32), Ports: PortRange{22, 22}}},
		Protos: []uint8{ProtoTCP},
	}}
}

func TestInboundRules(t *testing.T) {
	f := New()
	if f.Inbound(ipv4(ProtoTCP, peerA, self, 5000, 22)) {
		t.Fatal("admitted a packet before rules were set")
	}
	f.SetRules(rules())
	f.PingPort = 7
	tests := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"allowed port", ipv4(ProtoTCP, peerA, self, 5000, 22), true},
		{"other port", ipv4(ProtoTCP, peerA, self, 5000, 80), false},
		{"other source", ipv4(ProtoTCP, peerB, self, 5000, 22), false},
		{"other protocol", ipv4(ProtoUDP, peerA, self, 5000, 22), false},
		{"echo request needs any rule to the address", icmp(icmpEchoRequest, peerA, self, 1), false},
		{"echo request from a stranger", icmp(icmpEchoRequest, peerB, self, 1), false},
		{"unreachable is a reply", icmp(3, peerB, self, 0), true},
		{"ping service from a stranger", ipv4(ProtoUDP, peerB, self, 5000, 7), false},
		{"truncated", []byte{0x45, 0}, false},
		{"ipv6", append([]byte{0x60}, make([]byte, 39)...), false},
	}
	for _, tt := range tests {
		if got := f.Inbound(tt.pkt); got != tt.want {
			t.Errorf("%s: Inbound = %v, want %v", tt.name, got, tt.want)
		}
	}

	// A rule for any protocol lets ICMP echo and the ping port through.
	f.SetRules([]Rule{{
		Srcs: []netip.Prefix{netip.PrefixFrom(peerA, 32)},
		Dsts: []Dst{{Prefix: netip.PrefixFrom(self, 32), Ports: PortRange{443, 443}}},
	}})
	if !f.Inbound(icmp(icmpEchoRequest, peerA, self, 1)) {
		t.Error("echo request refused despite a rule to the address")
	}
	if !f.Inbound(ipv4(ProtoUDP, peerA, self, 5000, 7)) {
		t.Error("ping service refused despite a rule to the address")
	}
}

func TestRepliesToOutboundFlows(t *testing.T) {
	f := New()
	f.SetRules(nil) // nothing may connect in
	now := time.Unix(1000, 0)
	f.now = func() time.Time { return now }

	f.Outbound(ipv4(ProtoTCP, self, peerB, 40000, 443))
	if !f.Inbound(ipv4(ProtoTCP, peerB, self, 443, 40000)) {
		t.Fatal("reply to an outbound TCP flow refused")
	}
	if f.Inbound(ipv4(ProtoTCP, peerB, self, 443, 40001)) {
		t.Fatal("packet to another local port admitted")
	}
	if f.Inbound(ipv4(ProtoTCP, peerB, self, 40000, 22)) {
		t.Fatal("new connection from the peer admitted")
	}

	f.Outbound(icmp(icmpEchoRequest, self, peerB, 9))
	if !f.Inbound(icmp(icmpEchoReply, peerB, self, 9)) {
		t.Fatal("echo reply refused")
	}

	f.Outbound(ipv4(ProtoUDP, self, peerB, 5353, 53))
	now = now.Add(flowTTL + time.Second)
	if f.Inbound(ipv4(ProtoUDP, peerB, self, 53, 5353)) {
		t.Fatal("reply admitted after the flow expired")
	}
	if !f.Inbound(ipv4(ProtoTCP, peerB, self, 443, 40000)) {
		t.Fatal("TCP flow expired as early as UDP")
	}
}

func TestFlowTableBounded(t *testing.T) {
	f := New()
	for i := range maxFlows + 10 {
		f.Outbound(ipv4(ProtoUDP, self, peerB, uint16(i%65535)+1, uint16(i/65535)+1))
	}
	if len(f.flows) > maxFlows {
		t.Fatalf("%d flows tracked, max %d", len(f.flows), maxFlows)
	}
}

func TestAllowed(t *testing.T) {
	r := rules()
	if ok, i := Allowed(r, peerA, self, ProtoTCP, 22); !ok || i != 0 {
		t.Fatalf("Allowed = %v, %d", ok, i)
	}
	if ok, _ := Allowed(r, peerA, self, ProtoTCP, 23); ok {
		t.Fatal("Allowed on the wrong port")
	}
}
