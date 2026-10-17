// Package policy parses the mesh access-control policy and compiles it into
// packet-filter rules and peer visibility for each node.
//
// A policy is HuJSON (JSON with comments and trailing commas):
//
//	{
//	  "hosts": {"office": "10.1.0.0/24"},
//	  "acls": [
//	    // Developers may SSH to servers and reach the office LAN.
//	    {"action": "accept", "src": ["tag:dev"], "dst": ["tag:server:22", "office:*"]},
//	  ],
//	  "autoApprovers": {"routes": {"10.1.0.0/24": ["tag:router"]}, "exitNode": ["tag:exit"]},
//	  "tests": [{"src": "tag:dev", "accept": ["tag:server:22"], "deny": ["tag:server:80"]}],
//	}
//
// Selectors name traffic sources and destinations: "*" (anything),
// "tag:<name>" (nodes with that tag), a node name, a host alias from
// "hosts", or an IP address or CIDR prefix. Destinations add ports:
// "<selector>:<ports>" where ports is "*", a port, a range "8000-8999" or a
// comma-separated list of those. Anything not accepted by a rule is denied.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"

	"github.com/sneakybugmaster/transporter/internal/filter"
)

// Default is the policy of a new coordinator: every node may reach every
// other node (and every approved route) on any port.
const Default = `// Access-control policy. Traffic not accepted by a rule is dropped.
// Selectors: "*", "tag:<name>", node names, host aliases, IPs and CIDRs.
// Destinations add ports: "tag:web:80,443", "10.0.0.0/24:*".
{
  "hosts": {},
  "acls": [
    // Allow everything between all nodes, including approved routes.
    {"action": "accept", "src": ["*"], "dst": ["*:*"]},
  ],
  "autoApprovers": {
    // Routes advertised by matching nodes are approved without an admin.
    // "routes": {"10.0.0.0/8": ["tag:router"]},
    // "exitNode": ["tag:exit"],
  },
  "tests": [],
}
`

// Policy is a parsed policy document.
type Policy struct {
	Hosts         map[string]string `json:"hosts,omitempty"`
	ACLs          []ACL             `json:"acls"`
	AutoApprovers AutoApprovers     `json:"autoApprovers,omitzero"`
	Tests         []Test            `json:"tests,omitempty"`

	hosts map[string]netip.Prefix
	acls  []acl
}

// ACL is one rule as written.
type ACL struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
	// Proto restricts the rule to "tcp", "udp" or "icmp"; empty means any.
	Proto string `json:"proto,omitempty"`
}

// AutoApprovers names nodes whose advertised routes need no admin approval.
type AutoApprovers struct {
	// Routes maps a prefix to the nodes that may advertise it or any prefix
	// inside it.
	Routes map[string][]string `json:"routes,omitempty"`
	// ExitNode lists nodes that may become exit nodes.
	ExitNode []string `json:"exitNode,omitempty"`
}

// Test is an assertion checked whenever the policy is saved.
type Test struct {
	Src    string   `json:"src"`
	Proto  string   `json:"proto,omitempty"`
	Accept []string `json:"accept,omitempty"`
	Deny   []string `json:"deny,omitempty"`
}

type acl struct {
	src    []selector
	dst    []dstSpec
	protos []uint8
}

type dstSpec struct {
	sel   selector
	ports []filter.PortRange
}

// selector is a parsed source or destination host.
type selector struct {
	any    bool
	tag    string
	name   string
	prefix netip.Prefix
}

var (
	tagRE  = regexp.MustCompile(`^tag:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidTag reports whether s is a well-formed tag such as "tag:web".
func ValidTag(s string) bool { return tagRE.MatchString(s) }

// Parse parses and validates a policy.
func Parse(text []byte) (*Policy, error) {
	std, err := hujson.Standardize(text)
	if err != nil {
		return nil, fmt.Errorf("syntax: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("syntax: %w", err)
	}
	p.hosts = map[string]netip.Prefix{}
	for name, v := range p.Hosts {
		if !nameRE.MatchString(name) {
			return nil, fmt.Errorf("hosts: %q is not a valid alias (lowercase letters, digits and hyphens)", name)
		}
		pfx, err := parsePrefix(v)
		if err != nil {
			return nil, fmt.Errorf("hosts: %s: %w", name, err)
		}
		p.hosts[name] = pfx
	}
	for i, a := range p.ACLs {
		c, err := p.compileACL(a)
		if err != nil {
			return nil, fmt.Errorf("acls[%d]: %w", i, err)
		}
		p.acls = append(p.acls, c)
	}
	for pfx, sels := range p.AutoApprovers.Routes {
		if _, err := parsePrefix(pfx); err != nil {
			return nil, fmt.Errorf("autoApprovers.routes: %w", err)
		}
		for _, s := range sels {
			if _, err := p.parseSelector(s); err != nil {
				return nil, fmt.Errorf("autoApprovers.routes[%s]: %w", pfx, err)
			}
		}
	}
	for _, s := range p.AutoApprovers.ExitNode {
		if _, err := p.parseSelector(s); err != nil {
			return nil, fmt.Errorf("autoApprovers.exitNode: %w", err)
		}
	}
	for i, t := range p.Tests {
		if _, err := p.parseSelector(t.Src); err != nil {
			return nil, fmt.Errorf("tests[%d].src: %w", i, err)
		}
		if _, err := parseProto(t.Proto); err != nil {
			return nil, fmt.Errorf("tests[%d]: %w", i, err)
		}
		for _, d := range slices.Concat(t.Accept, t.Deny) {
			if _, err := p.parseDst(d); err != nil {
				return nil, fmt.Errorf("tests[%d]: %w", i, err)
			}
		}
	}
	return &p, nil
}

func (p *Policy) compileACL(a ACL) (acl, error) {
	if a.Action != "accept" {
		return acl{}, fmt.Errorf(`action must be "accept", got %q`, a.Action)
	}
	if len(a.Src) == 0 || len(a.Dst) == 0 {
		return acl{}, errors.New("src and dst must not be empty")
	}
	var c acl
	var err error
	if c.protos, err = parseProto(a.Proto); err != nil {
		return acl{}, err
	}
	for _, s := range a.Src {
		sel, err := p.parseSelector(s)
		if err != nil {
			return acl{}, fmt.Errorf("src: %w", err)
		}
		c.src = append(c.src, sel)
	}
	for _, d := range a.Dst {
		spec, err := p.parseDst(d)
		if err != nil {
			return acl{}, fmt.Errorf("dst: %w", err)
		}
		c.dst = append(c.dst, spec)
	}
	return c, nil
}

func parseProto(s string) ([]uint8, error) {
	switch strings.ToLower(s) {
	case "", "*":
		return nil, nil
	case "tcp":
		return []uint8{filter.ProtoTCP}, nil
	case "udp":
		return []uint8{filter.ProtoUDP}, nil
	case "icmp":
		return []uint8{filter.ProtoICMP}, nil
	}
	return nil, fmt.Errorf(`proto must be "tcp", "udp" or "icmp", got %q`, s)
}

func (p *Policy) parseSelector(s string) (selector, error) {
	switch {
	case s == "*":
		return selector{any: true}, nil
	case strings.HasPrefix(s, "tag:"):
		if !ValidTag(s) {
			return selector{}, fmt.Errorf("invalid tag %q", s)
		}
		return selector{tag: s}, nil
	}
	if pfx, ok := p.hosts[s]; ok {
		return selector{prefix: pfx}, nil
	}
	if pfx, err := parsePrefix(s); err == nil {
		return selector{prefix: pfx}, nil
	}
	if nameRE.MatchString(s) {
		return selector{name: s}, nil
	}
	return selector{}, fmt.Errorf("%q is not a tag, node name, host alias, IP or CIDR", s)
}

func (p *Policy) parseDst(s string) (dstSpec, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return dstSpec{}, fmt.Errorf("%q needs ports, e.g. %q or %q", s, s+":*", s+":443")
	}
	sel, err := p.parseSelector(s[:i])
	if err != nil {
		return dstSpec{}, err
	}
	ports, err := parsePorts(s[i+1:])
	if err != nil {
		return dstSpec{}, fmt.Errorf("%q: %w", s, err)
	}
	return dstSpec{sel: sel, ports: ports}, nil
}

func parsePorts(s string) ([]filter.PortRange, error) {
	if s == "*" {
		return []filter.PortRange{filter.AllPorts}, nil
	}
	var out []filter.PortRange
	for part := range strings.SplitSeq(s, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.ParseUint(lo, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("bad port %q", part)
		}
		last := first
		if isRange {
			if last, err = strconv.ParseUint(hi, 10, 16); err != nil || last < first {
				return nil, fmt.Errorf("bad port range %q", part)
			}
		}
		out = append(out, filter.PortRange{First: uint16(first), Last: uint16(last)})
	}
	return out, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			return netip.Prefix{}, fmt.Errorf("invalid IPv4 prefix %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 address %q", s)
	}
	return netip.PrefixFrom(a, 32), nil
}

// Node is what the policy needs to know about a mesh member.
type Node struct {
	Name string
	IP   netip.Addr
	Tags []string
	// Routes are the node's approved subnet routes (0.0.0.0/0 for an exit
	// node).
	Routes []netip.Prefix
}

// owned returns the prefixes traffic to which is delivered by the node.
func (n Node) owned() []netip.Prefix {
	return append([]netip.Prefix{netip.PrefixFrom(n.IP, 32)}, n.Routes...)
}

func (s selector) matches(n Node) bool {
	switch {
	case s.any:
		return true
	case s.tag != "":
		return slices.Contains(n.Tags, s.tag)
	case s.name != "":
		return s.name == n.Name
	}
	return s.prefix.Contains(n.IP)
}

// resolve returns the prefixes a selector stands for.
func (s selector) resolve(nodes []Node) []netip.Prefix {
	switch {
	case s.any:
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	case s.tag != "" || s.name != "":
		var out []netip.Prefix
		for _, n := range nodes {
			if s.matches(n) {
				out = append(out, netip.PrefixFrom(n.IP, 32))
			}
		}
		return out
	}
	return []netip.Prefix{s.prefix}
}

// Compiled is a policy resolved against the current set of nodes.
type Compiled struct {
	rules []filter.Rule
}

// Compile resolves the policy's selectors against nodes.
func (p *Policy) Compile(nodes []Node) *Compiled {
	c := &Compiled{}
	for _, a := range p.acls {
		var r filter.Rule
		r.Protos = a.protos
		for _, s := range a.src {
			r.Srcs = append(r.Srcs, s.resolve(nodes)...)
		}
		for _, d := range a.dst {
			for _, pfx := range d.sel.resolve(nodes) {
				for _, ports := range d.ports {
					r.Dsts = append(r.Dsts, filter.Dst{Prefix: pfx, Ports: ports})
				}
			}
		}
		c.rules = append(c.rules, r)
	}
	return c
}

// Rules returns every compiled rule, in policy order.
func (c *Compiled) Rules() []filter.Rule { return c.rules }

// FilterFor returns the rules node n enforces on inbound traffic: those
// with a destination n delivers, narrowed to what n delivers.
func (c *Compiled) FilterFor(n Node) []filter.Rule {
	owned := n.owned()
	var out []filter.Rule
	for _, r := range c.rules {
		var dsts []filter.Dst
		for _, d := range r.Dsts {
			for _, o := range owned {
				if pfx, ok := intersect(d.Prefix, o); ok {
					dsts = append(dsts, filter.Dst{Prefix: pfx, Ports: d.Ports})
				}
			}
		}
		if len(dsts) > 0 && len(r.Srcs) > 0 {
			out = append(out, filter.Rule{Srcs: r.Srcs, Dsts: dsts, Protos: r.Protos})
		}
	}
	return out
}

// CanReach reports whether some rule lets node from send anything to node
// to (its address or its routes).
func (c *Compiled) CanReach(from, to Node) bool {
	owned := to.owned()
	for _, r := range c.rules {
		if !containsAddr(r.Srcs, from.IP) {
			continue
		}
		for _, d := range r.Dsts {
			for _, o := range owned {
				if d.Prefix.Overlaps(o) {
					return true
				}
			}
		}
	}
	return false
}

// Visible reports whether two nodes need to know about each other: one of
// them may open connections to the other.
func (c *Compiled) Visible(a, b Node) bool { return c.CanReach(a, b) || c.CanReach(b, a) }

// Allowed reports whether a packet from src to dst would be admitted by
// the destination, returning the index of the first matching ACL.
func (c *Compiled) Allowed(src, dst netip.Addr, proto uint8, port uint16) (bool, int) {
	return filter.Allowed(c.rules, src, dst, proto, port)
}

// AutoApproved returns the subset of advertised routes node n may use
// without an administrator's approval.
func (p *Policy) AutoApproved(n Node, advertised []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range advertised {
		if r.Bits() == 0 {
			if p.anyMatches(p.AutoApprovers.ExitNode, n) {
				out = append(out, r)
			}
			continue
		}
		for pfxStr, sels := range p.AutoApprovers.Routes {
			pfx, err := parsePrefix(pfxStr)
			if err == nil && pfx.Bits() <= r.Bits() && pfx.Contains(r.Addr()) && p.anyMatches(sels, n) {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

func (p *Policy) anyMatches(sels []string, n Node) bool {
	for _, s := range sels {
		if sel, err := p.parseSelector(s); err == nil && sel.matches(n) {
			return true
		}
	}
	return false
}

// RunTests checks the policy's tests against nodes and returns one error per
// failed assertion.
func (p *Policy) RunTests(nodes []Node) []error {
	c := p.Compile(nodes)
	var errs []error
	for _, t := range p.Tests {
		srcSel, _ := p.parseSelector(t.Src)
		srcs := srcSel.resolve(nodes)
		if len(srcs) == 0 {
			errs = append(errs, fmt.Errorf("test src %q matches no node", t.Src))
			continue
		}
		protos, _ := parseProto(t.Proto)
		proto := filter.ProtoTCP
		if len(protos) > 0 {
			proto = protos[0]
		}
		check := func(dst string, want bool) {
			spec, _ := p.parseDst(dst)
			dsts := spec.sel.resolve(nodes)
			if len(dsts) == 0 {
				errs = append(errs, fmt.Errorf("test dst %q matches no node", dst))
				return
			}
			for _, s := range srcs {
				for _, d := range dsts {
					for _, ports := range spec.ports {
						for _, port := range []uint16{ports.First, ports.Last} {
							if ok, _ := c.Allowed(s.Addr(), d.Addr(), proto, port); ok != want {
								verb := "accept"
								if !want {
									verb = "deny"
								}
								errs = append(errs, fmt.Errorf("test failed: %s -> %s should %s, but the policy does not", t.Src, dst, verb))
								return
							}
						}
					}
				}
			}
		}
		for _, d := range t.Accept {
			check(d, true)
		}
		for _, d := range t.Deny {
			check(d, false)
		}
	}
	return errs
}

func containsAddr(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// intersect returns the overlap of two prefixes (the more specific one).
func intersect(a, b netip.Prefix) (netip.Prefix, bool) {
	if !a.Overlaps(b) {
		return netip.Prefix{}, false
	}
	if a.Bits() >= b.Bits() {
		return a, true
	}
	return b, true
}
