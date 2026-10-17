package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"

	"github.com/sneakybugmaster/transporter/internal/coordinator/control"
	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
	"github.com/sneakybugmaster/transporter/internal/filter"
	"github.com/sneakybugmaster/transporter/internal/policy"
)

const maxPolicy = 60 << 10 // the request body limit is 64 KiB

func (s *Server) GetPolicy(w http.ResponseWriter, r *http.Request) {
	_, text, err := s.ctl.Policy(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, Policy{Policy: text})
}

func (s *Server) SetPolicy(w http.ResponseWriter, r *http.Request) {
	var req Policy
	if !decode(w, r, &req) {
		return
	}
	if len(req.Policy) > maxPolicy {
		writePolicyError(w, []string{"policy is too large"})
		return
	}
	_, err := s.ctl.SetPolicy(r.Context(), req.Policy)
	var pe *control.PolicyError
	if errors.As(err, &pe) {
		writePolicyError(w, pe.Errors)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, "policy.update", "", "")
	s.log.Info("policy updated", "by", admin(r).Username)
	writeJSON(w, http.StatusOK, req)
}

func writePolicyError(w http.ResponseWriter, details []string) {
	writeJSON(w, http.StatusBadRequest, PolicyError{Error: "policy rejected", Details: details})
}

func (s *Server) CheckPolicy(w http.ResponseWriter, r *http.Request) {
	var req PolicyCheck
	if !decode(w, r, &req) {
		return
	}
	ctx := r.Context()
	var (
		p   *policy.Policy
		err error
	)
	if req.Policy != nil {
		if p, err = policy.Parse([]byte(*req.Policy)); err != nil {
			writePolicyError(w, []string{err.Error()})
			return
		}
	} else if p, _, err = s.ctl.Policy(ctx); err != nil {
		s.internal(w, err)
		return
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		s.internal(w, err)
		return
	}
	src, err := endpointAddr(req.Src, nodes)
	if err != nil {
		writePolicyError(w, []string{"src: " + err.Error()})
		return
	}
	dst, err := endpointAddr(req.Dst, nodes)
	if err != nil {
		writePolicyError(w, []string{"dst: " + err.Error()})
		return
	}
	if req.Port < 0 || req.Port > 65535 {
		writePolicyError(w, []string{"port must be between 0 and 65535"})
		return
	}
	proto, protoName := filter.ProtoTCP, "tcp"
	if req.Proto != nil {
		protoName = string(*req.Proto)
		switch protoName {
		case "udp":
			proto = filter.ProtoUDP
		case "icmp":
			proto = filter.ProtoICMP
		}
	}
	pnodes := make([]policy.Node, len(nodes))
	for i, n := range nodes {
		pnodes[i] = policy.Node{Name: n.Name, IP: n.IPv4, Tags: n.Tags, Routes: n.Routes()}
	}
	ok, idx := p.Compile(pnodes).Allowed(src, dst, proto, uint16(req.Port)) //nolint:gosec // range checked above
	res := PolicyCheckResult{Allowed: ok, SrcAddr: src.String(), DstAddr: dst.String()}
	target := fmt.Sprintf("%s %s:%d", protoName, dst, req.Port)
	if protoName == "icmp" {
		target = "icmp " + dst.String()
	}
	if ok {
		res.Rule = &idx
		res.Reason = fmt.Sprintf("acls[%d] accepts %s -> %s", idx, src, target)
	} else {
		res.Reason = fmt.Sprintf("no rule accepts %s -> %s; it is dropped", src, target)
	}
	if ok && !delivered(dst, nodes) {
		res.Reason += " (but no node owns that address or an approved route to it)"
	}
	writeJSON(w, http.StatusOK, res)
}

// endpointAddr resolves a node name or an IPv4 address.
func endpointAddr(s string, nodes []store.Node) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		if !a.Is4() {
			return netip.Addr{}, errors.New("only IPv4 is supported")
		}
		return a, nil
	}
	for _, n := range nodes {
		if n.Name == s {
			return n.IPv4, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%q is neither a node name nor an IPv4 address", s)
}

func delivered(a netip.Addr, nodes []store.Node) bool {
	for _, n := range nodes {
		if n.IPv4 == a || slices.ContainsFunc(n.Routes(), func(p netip.Prefix) bool { return p.Contains(a) }) {
			return true
		}
	}
	return false
}

func (s *Server) GetDNS(w http.ResponseWriter, r *http.Request) {
	c, err := s.ctl.DNS(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, dnsJSON(c))
}

func (s *Server) SetDNS(w http.ResponseWriter, r *http.Request) {
	var req DNSConfig
	if !decode(w, r, &req) {
		return
	}
	c := control.DNSConfig{MagicDNS: req.MagicDNS, Domain: req.Domain}
	for _, sd := range req.Split {
		c.Split = append(c.Split, control.SplitDNS{Domain: sd.Domain, Resolvers: sd.Resolvers})
	}
	c, err := s.ctl.SetDNS(r.Context(), c)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.audit(r, "dns.update", c.Domain, fmt.Sprintf("magicDNS=%v, %d split domains", c.MagicDNS, len(c.Split)))
	writeJSON(w, http.StatusOK, dnsJSON(c))
}

func dnsJSON(c control.DNSConfig) DNSConfig {
	out := DNSConfig{MagicDNS: c.MagicDNS, Domain: c.Domain, Split: []SplitDNS{}}
	for _, sd := range c.Split {
		out.Split = append(out.Split, SplitDNS{Domain: sd.Domain, Resolvers: sd.Resolvers})
	}
	return out
}

func (s *Server) GetTopology(w http.ResponseWriter, _ *http.Request) {
	links := []TopologyLink{}
	for from, peers := range s.ctl.Topology() {
		for _, p := range peers {
			l := TopologyLink{From: from, To: p.NodeID, Path: TopologyLinkPath(p.Path)}
			if p.LatencyMs > 0 {
				lat := p.LatencyMs
				l.LatencyMs = &lat
			}
			links = append(links, l)
		}
	}
	slices.SortFunc(links, func(a, b TopologyLink) int {
		if c := strings.Compare(a.From, b.From); c != 0 {
			return c
		}
		return strings.Compare(a.To, b.To)
	})
	writeJSON(w, http.StatusOK, Topology{Links: links})
}

func (s *Server) ListAudit(w http.ResponseWriter, r *http.Request, params ListAuditParams) {
	limit := 100
	if params.Limit != nil {
		limit = min(max(*params.Limit, 1), 500)
	}
	var before int64
	if params.Before != nil {
		before = *params.Before
	}
	entries, err := s.store.ListAudit(r.Context(), limit, before)
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]AuditEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, AuditEntry{Id: e.ID, Time: e.Time, Actor: e.Actor, Action: e.Action, Target: e.Target, Detail: e.Detail})
	}
	writeJSON(w, http.StatusOK, out)
}

// audit records an admin's change; failures are logged, not returned.
func (s *Server) audit(r *http.Request, action, target, detail string) {
	s.auditAs(r.Context(), admin(r).Username, action, target, detail)
}

func (s *Server) auditAs(ctx context.Context, actor, action, target, detail string) {
	if err := s.store.AppendAudit(ctx, store.AuditEntry{Actor: actor, Action: action, Target: target, Detail: detail}); err != nil {
		s.log.Error("audit log", "err", err)
	}
}

// parseTags validates and de-duplicates tags.
func parseTags(in []string) ([]string, error) {
	out := []string{}
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if !policy.ValidTag(t) {
			return nil, fmt.Errorf("invalid tag %q: use tag:<name> with lowercase letters, digits and hyphens", t)
		}
		if !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	if len(out) > 32 {
		return nil, errors.New("at most 32 tags")
	}
	return out, nil
}

func parseRoutes(in []string) ([]netip.Prefix, error) {
	out := []netip.Prefix{}
	for _, r := range in {
		p, err := netip.ParsePrefix(strings.TrimSpace(r))
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("invalid route %q", r)
		}
		if p = p.Masked(); !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out, nil
}
