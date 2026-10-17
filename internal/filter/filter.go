// Package filter is the packet filter every agent applies to traffic that
// arrives from the mesh. The coordinator compiles the access-control policy
// into Rules for each node; the filter admits inbound packets a rule allows
// plus replies to connections the node opened itself.
package filter

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// IP protocol numbers used in rules.
const (
	ProtoICMP uint8 = 1
	ProtoTCP  uint8 = 6
	ProtoUDP  uint8 = 17
)

// PortRange is an inclusive range of ports; {0, 65535} is every port.
type PortRange struct {
	First, Last uint16
}

// AllPorts matches every port.
var AllPorts = PortRange{0, 65535}

// Contains reports whether port is in the range.
func (r PortRange) Contains(port uint16) bool { return port >= r.First && port <= r.Last }

// Dst is a destination prefix and the ports allowed on it.
type Dst struct {
	Prefix netip.Prefix
	Ports  PortRange
}

// Rule admits packets from any of Srcs to any of Dsts using one of Protos
// (any protocol when Protos is empty).
type Rule struct {
	Srcs   []netip.Prefix
	Dsts   []Dst
	Protos []uint8
}

// Match reports whether the rule admits a packet. Ports are ignored when
// anyPort is set (ICMP, and the agent's ping service).
func (r Rule) Match(src, dst netip.Addr, proto uint8, port uint16, anyPort bool) bool {
	if len(r.Protos) > 0 && !slices.Contains(r.Protos, proto) {
		return false
	}
	if !containsAddr(r.Srcs, src) {
		return false
	}
	for _, d := range r.Dsts {
		if d.Prefix.Contains(dst) && (anyPort || d.Ports.Contains(port)) {
			return true
		}
	}
	return false
}

// Allowed reports whether any rule admits the packet, returning its index
// or -1.
func Allowed(rules []Rule, src, dst netip.Addr, proto uint8, port uint16) (bool, int) {
	anyPort := proto == ProtoICMP
	for i, r := range rules {
		if r.Match(src, dst, proto, port, anyPort) {
			return true, i
		}
	}
	return false, -1
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

const (
	maxFlows   = 1 << 16
	tcpFlowTTL = 10 * time.Minute
	flowTTL    = 2 * time.Minute // UDP and ICMP
)

// flowKey identifies a flow from the local side's point of view.
type flowKey struct {
	proto         uint8
	local, remote netip.Addr
	lport, rport  uint16 // ICMP: echo identifier in both
}

// Filter is a stateful packet filter. It is safe for concurrent use.
type Filter struct {
	rules atomic.Pointer[[]Rule]
	// PingPort is a UDP port that is treated like ICMP echo: open to every
	// peer a rule lets reach this node on any port.
	PingPort uint16

	mu    sync.Mutex
	flows map[flowKey]time.Time // expiry
	now   func() time.Time
}

// New returns a filter that drops every inbound packet until SetRules is
// called.
func New() *Filter {
	return &Filter{flows: map[flowKey]time.Time{}, now: time.Now}
}

// SetRules replaces the rules.
func (f *Filter) SetRules(rules []Rule) { f.rules.Store(&rules) }

// Rules returns the current rules.
func (f *Filter) Rules() []Rule {
	if r := f.rules.Load(); r != nil {
		return *r
	}
	return nil
}

// Outbound records a packet this node sends into the mesh, so replies to it
// are admitted.
func (f *Filter) Outbound(pkt []byte) {
	p, ok := parse(pkt)
	if !ok || p.fragment {
		return
	}
	key := flowKey{proto: p.proto, local: p.src, remote: p.dst, lport: p.sport, rport: p.dport}
	switch p.proto {
	case ProtoTCP:
	case ProtoUDP:
	case ProtoICMP:
		if p.icmpType != icmpEchoRequest {
			return
		}
	default:
		return
	}
	ttl := flowTTL
	if p.proto == ProtoTCP {
		ttl = tcpFlowTTL
	}
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.flows[key]; !ok && len(f.flows) >= maxFlows {
		f.sweepLocked(now)
	}
	f.flows[key] = now.Add(ttl)
}

// sweepLocked drops expired flows, and half of the rest if that is not enough.
func (f *Filter) sweepLocked(now time.Time) {
	for k, exp := range f.flows {
		if now.After(exp) {
			delete(f.flows, k)
		}
	}
	if len(f.flows) < maxFlows {
		return
	}
	n := 0
	for k := range f.flows {
		if n%2 == 0 {
			delete(f.flows, k)
		}
		n++
	}
}

// Inbound reports whether a packet that arrived from the mesh may be
// delivered.
func (f *Filter) Inbound(pkt []byte) bool {
	p, ok := parse(pkt)
	if !ok {
		return false
	}
	if p.proto == ProtoICMP && p.icmpType != icmpEchoRequest && !p.fragment {
		// Echo replies, unreachables and time-exceeded answer something
		// this node sent; they carry no new connection.
		return true
	}
	if !p.fragment {
		key := flowKey{proto: p.proto, local: p.dst, remote: p.src, lport: p.dport, rport: p.sport}
		if p.proto == ProtoICMP {
			key.lport, key.rport = p.sport, p.dport
		}
		f.mu.Lock()
		exp, ok := f.flows[key]
		f.mu.Unlock()
		if ok && f.now().Before(exp) {
			return true
		}
	}
	anyPort := p.fragment || p.proto == ProtoICMP || (p.proto == ProtoUDP && f.PingPort != 0 && p.dport == f.PingPort)
	for _, r := range f.Rules() {
		if r.Match(p.src, p.dst, p.proto, p.dport, anyPort) {
			return true
		}
	}
	return false
}

const (
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

type packet struct {
	proto        uint8
	src, dst     netip.Addr
	sport, dport uint16
	icmpType     uint8
	// fragment is set for non-first fragments, which carry no ports.
	fragment bool
}

// parse extracts what the filter needs from an IPv4 packet. Anything else
// (IPv6, truncated or malformed packets) is reported as not ok.
func parse(b []byte) (packet, bool) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return packet{}, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return packet{}, false
	}
	p := packet{
		proto: b[9],
		src:   netip.AddrFrom4([4]byte(b[12:16])),
		dst:   netip.AddrFrom4([4]byte(b[16:20])),
	}
	if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
		p.fragment = true
		return p, true
	}
	l4 := b[ihl:]
	switch p.proto {
	case ProtoTCP, ProtoUDP:
		if len(l4) < 4 {
			return packet{}, false
		}
		p.sport = binary.BigEndian.Uint16(l4[0:2])
		p.dport = binary.BigEndian.Uint16(l4[2:4])
	case ProtoICMP:
		if len(l4) < 8 {
			return packet{}, false
		}
		p.icmpType = l4[0]
		if p.icmpType == icmpEchoRequest || p.icmpType == icmpEchoReply {
			id := binary.BigEndian.Uint16(l4[4:6])
			p.sport, p.dport = id, id
		}
	}
	return p, true
}
