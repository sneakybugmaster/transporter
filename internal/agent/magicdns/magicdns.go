// Package magicdns is the agent's DNS resolver. It answers names of mesh
// nodes (<node>.<domain>) from the netmap and forwards split-DNS domains to
// their configured resolvers. In TUN mode the agent serves it at Addr,
// intercepting queries before they reach WireGuard, so no socket needs to be
// bound and nothing leaves the machine for mesh names.
package magicdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Addr is where the resolver answers. It lies inside the default mesh prefix
// and is never assigned to a node.
var Addr = netip.MustParseAddr("100.100.100.100")

const (
	ttl            = 60
	forwardTimeout = 4 * time.Second
	// maxUDPSize keeps answers unfragmented on common paths (DNS flag day
	// 2020); longer answers are truncated so clients retry over TCP.
	maxUDPSize = 1232
)

// Split sends queries for Domain (and its subdomains) to Resolvers.
type Split struct {
	Domain    string
	Resolvers []netip.AddrPort
}

// Config is the resolver's view of the mesh.
type Config struct {
	// Domain is the suffix of node names, e.g. "mesh.internal"; empty
	// disables answering for nodes.
	Domain string
	// Nodes maps node names to addresses.
	Nodes map[string]netip.Addr
	Split []Split
}

// Resolver answers DNS queries. It is safe for concurrent use.
type Resolver struct {
	// Dial connects to upstream resolvers of split domains; nil uses the
	// host network.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)

	mu      sync.RWMutex
	domain  string
	names   map[string]netip.Addr // fqdn without trailing dot -> address
	reverse map[netip.Addr]string
	split   []Split
}

// SetConfig replaces the resolver's configuration.
func (r *Resolver) SetConfig(c Config) {
	domain := strings.ToLower(strings.Trim(c.Domain, "."))
	names := make(map[string]netip.Addr, len(c.Nodes))
	reverse := make(map[netip.Addr]string, len(c.Nodes))
	if domain != "" {
		for name, ip := range c.Nodes {
			fqdn := strings.ToLower(name) + "." + domain
			names[fqdn] = ip
			reverse[ip] = fqdn
		}
	}
	split := make([]Split, len(c.Split))
	for i, s := range c.Split {
		split[i] = Split{Domain: strings.ToLower(strings.Trim(s.Domain, ".")), Resolvers: s.Resolvers}
	}
	r.mu.Lock()
	r.domain, r.names, r.reverse, r.split = domain, names, reverse, split
	r.mu.Unlock()
}

// Domains returns the domains the resolver is authoritative for or forwards,
// for configuring the OS: queries for these should be sent to Addr.
func (r *Resolver) Domains() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	if r.domain != "" {
		out = append(out, r.domain)
	}
	for _, s := range r.split {
		out = append(out, s.Domain)
	}
	return out
}

// Lookup resolves a mesh name: "node" or "node.<domain>".
func (r *Resolver) Lookup(name string) (netip.Addr, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.domain == "" {
		return netip.Addr{}, false
	}
	if ip, ok := r.names[name]; ok {
		return ip, true
	}
	ip, ok := r.names[name+"."+r.domain]
	return ip, ok
}

// Handle answers one DNS message (UDP wire format). It returns nil for
// messages that are not worth answering (not a query, unparseable).
func (r *Resolver) Handle(ctx context.Context, query []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return reply(h, nil, dnsmessage.RCodeFormatError, nil)
	}
	if h.OpCode != 0 {
		return reply(h, &q, dnsmessage.RCodeNotImplemented, nil)
	}
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))

	r.mu.RLock()
	domain := r.domain
	ip, known := r.names[name]
	revName, revKnown := r.reverse[ptrAddr(name)]
	upstream := r.splitFor(name)
	r.mu.RUnlock()

	switch {
	case q.Class != dnsmessage.ClassINET:
		return reply(h, &q, dnsmessage.RCodeRefused, nil)
	case known:
		var answers []dnsmessage.Resource
		if q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeALL {
			answers = append(answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
				Body:   &dnsmessage.AResource{A: ip.As4()},
			})
		}
		return reply(h, &q, dnsmessage.RCodeSuccess, answers) // other types: no data
	case revKnown && q.Type == dnsmessage.TypePTR:
		target, err := dnsmessage.NewName(revName + ".")
		if err != nil {
			return reply(h, &q, dnsmessage.RCodeServerFailure, nil)
		}
		return reply(h, &q, dnsmessage.RCodeSuccess, []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: ttl},
			Body:   &dnsmessage.PTRResource{PTR: target},
		}})
	case domain != "" && (name == domain || strings.HasSuffix(name, "."+domain)):
		if name == domain {
			return reply(h, &q, dnsmessage.RCodeSuccess, nil)
		}
		return reply(h, &q, dnsmessage.RCodeNameError, nil)
	case upstream != nil:
		if resp := r.forward(ctx, query, upstream); resp != nil {
			return resp
		}
		return reply(h, &q, dnsmessage.RCodeServerFailure, nil)
	}
	return reply(h, &q, dnsmessage.RCodeRefused, nil)
}

// splitFor returns the resolvers for the longest matching split domain.
func (r *Resolver) splitFor(name string) []netip.AddrPort {
	var best *Split
	for i := range r.split {
		s := &r.split[i]
		if (name == s.Domain || strings.HasSuffix(name, "."+s.Domain)) && (best == nil || len(s.Domain) > len(best.Domain)) {
			best = s
		}
	}
	if best == nil {
		return nil
	}
	return best.Resolvers
}

// forward relays the query to each resolver in turn until one answers.
func (r *Resolver) forward(ctx context.Context, query []byte, resolvers []netip.AddrPort) []byte {
	dial := r.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	for _, rs := range resolvers {
		resp, err := exchange(ctx, dial, rs, query)
		if err == nil {
			return resp
		}
	}
	return nil
}

func exchange(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), server netip.AddrPort, query []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, forwardTimeout)
	defer cancel()
	conn, err := dial(ctx, "udp", server.String())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 64<<10)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		// Ignore anything that is not the answer to our question.
		if n >= 2 && len(query) >= 2 && buf[0] == query[0] && buf[1] == query[1] {
			return truncate(buf[:n]), nil
		}
	}
}

// truncate shortens an over-long upstream answer to a header-only reply
// with the TC bit, telling the client to retry over TCP.
func truncate(resp []byte) []byte {
	if len(resp) <= maxUDPSize {
		return resp
	}
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	h.Truncated = true
	b := dnsmessage.NewBuilder(nil, h)
	_ = b.StartQuestions()
	_ = b.Question(q)
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

func reply(q dnsmessage.Header, question *dnsmessage.Question, rcode dnsmessage.RCode, answers []dnsmessage.Resource) []byte {
	h := dnsmessage.Header{
		ID:                 q.ID,
		Response:           true,
		OpCode:             q.OpCode,
		Authoritative:      rcode == dnsmessage.RCodeSuccess || rcode == dnsmessage.RCodeNameError,
		RecursionDesired:   q.RecursionDesired,
		RecursionAvailable: true,
		RCode:              rcode,
	}
	b := dnsmessage.NewBuilder(nil, h)
	b.EnableCompression()
	if question != nil {
		if err := b.StartQuestions(); err != nil {
			return nil
		}
		if err := b.Question(*question); err != nil {
			return nil
		}
	}
	if err := b.StartAnswers(); err != nil {
		return nil
	}
	for _, a := range answers {
		var err error
		switch body := a.Body.(type) {
		case *dnsmessage.AResource:
			err = b.AResource(a.Header, *body)
		case *dnsmessage.PTRResource:
			err = b.PTRResource(a.Header, *body)
		default:
			err = errors.New("unsupported record")
		}
		if err != nil {
			return nil
		}
	}
	out, err := b.Finish()
	if err != nil {
		return nil
	}
	return out
}

// ptrAddr parses a reverse-lookup name such as 1.0.64.100.in-addr.arpa.
func ptrAddr(name string) netip.Addr {
	rest, ok := strings.CutSuffix(name, ".in-addr.arpa")
	if !ok {
		return netip.Addr{}
	}
	parts := strings.Split(rest, ".")
	if len(parts) != 4 {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0])
	if err != nil {
		return netip.Addr{}
	}
	return a
}
