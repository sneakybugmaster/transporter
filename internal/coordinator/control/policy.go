package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
	"github.com/sneakybugmaster/transporter/internal/policy"
)

// DNSConfig is the mesh's DNS configuration, stored as JSON.
type DNSConfig struct {
	// MagicDNS makes agents answer <node>.<Domain> at MagicDNSAddr.
	MagicDNS bool   `json:"magicDNS"`
	Domain   string `json:"domain"`
	// Split sends queries for these domains to specific resolvers.
	Split []SplitDNS `json:"split"`
}

// SplitDNS routes one domain to its resolvers.
type SplitDNS struct {
	Domain    string   `json:"domain"`
	Resolvers []string `json:"resolvers"`
}

// DefaultDNS is used until an admin changes it.
var DefaultDNS = DNSConfig{MagicDNS: true, Domain: "mesh.internal", Split: []SplitDNS{}}

var domainRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate normalises and checks the configuration.
func (c *DNSConfig) Validate() error {
	c.Domain = strings.ToLower(strings.Trim(strings.TrimSpace(c.Domain), "."))
	if !domainRE.MatchString(c.Domain) || len(c.Domain) > 200 {
		return fmt.Errorf("invalid domain %q", c.Domain)
	}
	if c.Split == nil {
		c.Split = []SplitDNS{}
	}
	if len(c.Split) > 32 {
		return errors.New("at most 32 split DNS domains")
	}
	for i := range c.Split {
		sd := &c.Split[i]
		sd.Domain = strings.ToLower(strings.Trim(strings.TrimSpace(sd.Domain), "."))
		if !domainRE.MatchString(sd.Domain) {
			return fmt.Errorf("invalid split DNS domain %q", sd.Domain)
		}
		if sd.Domain == c.Domain || strings.HasSuffix(c.Domain, "."+sd.Domain) {
			return fmt.Errorf("split DNS domain %q would hide the mesh domain", sd.Domain)
		}
		if len(sd.Resolvers) == 0 || len(sd.Resolvers) > 4 {
			return fmt.Errorf("%s: give 1 to 4 resolvers", sd.Domain)
		}
		for j, r := range sd.Resolvers {
			r = strings.TrimSpace(r)
			if ap, err := netip.ParseAddrPort(r); err == nil && ap.Addr().Is4() {
				sd.Resolvers[j] = ap.String()
				continue
			}
			a, err := netip.ParseAddr(r)
			if err != nil || !a.Is4() {
				return fmt.Errorf("%s: resolver %q is not an IPv4 address", sd.Domain, r)
			}
			sd.Resolvers[j] = a.String()
		}
	}
	return nil
}

// policyState caches the parsed policy and DNS settings.
type policyState struct {
	mu     sync.Mutex
	policy *policy.Policy
	text   string // source of policy
	// reports holds the latest peer paths reported by each node.
	reports map[string]statusReport
}

type statusReport struct {
	peers []PeerPath
	at    time.Time
}

// PeerPath is how a node reaches one of its peers.
type PeerPath struct {
	NodeID    string
	Path      string
	LatencyMs float64
}

// Policy returns the access-control policy and its source text. It reads
// the stored text every time (so changes made with the coordinator's CLI
// apply too) and parses it only when it changed.
func (s *Service) Policy(ctx context.Context) (*policy.Policy, string, error) {
	text, err := s.store.Setting(ctx, store.SettingPolicy)
	if err != nil {
		return nil, "", err
	}
	if text == "" {
		text = policy.Default
	}
	s.ps.mu.Lock()
	defer s.ps.mu.Unlock()
	if s.ps.policy != nil && s.ps.text == text {
		return s.ps.policy, s.ps.text, nil
	}
	p, err := policy.Parse([]byte(text))
	if err != nil {
		// A stored policy always parsed when it was saved; this means the
		// format changed incompatibly. Fail closed.
		return nil, "", fmt.Errorf("stored policy: %w", err)
	}
	s.ps.policy, s.ps.text = p, text
	return p, text, nil
}

// SetPolicy validates, stores and applies a new policy. Policy tests are
// checked against the current nodes; failures reject the change.
func (s *Service) SetPolicy(ctx context.Context, text string) (*policy.Policy, error) {
	p, err := policy.Parse([]byte(text))
	if err != nil {
		return nil, &PolicyError{Errors: []string{err.Error()}}
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	if errs := p.RunTests(policyNodes(nodes)); len(errs) > 0 {
		pe := &PolicyError{}
		for _, e := range errs {
			pe.Errors = append(pe.Errors, e.Error())
		}
		return nil, pe
	}
	if err := s.store.SetSetting(ctx, store.SettingPolicy, text); err != nil {
		return nil, err
	}
	s.ps.mu.Lock()
	s.ps.policy, s.ps.text = p, text
	s.ps.mu.Unlock()
	for _, n := range nodes {
		if _, err := s.autoApprove(ctx, n, p); err != nil {
			return nil, err
		}
	}
	s.hub.broadcast()
	return p, nil
}

// PolicyError lists why a policy was rejected.
type PolicyError struct{ Errors []string }

func (e *PolicyError) Error() string { return strings.Join(e.Errors, "; ") }

// KeyExpiry returns how long node keys last; zero means forever.
func (s *Service) KeyExpiry(ctx context.Context) (time.Duration, error) {
	v, err := s.store.Setting(ctx, store.SettingKeyExpiryDays)
	if err != nil || v == "" {
		return 0, err
	}
	days, err := strconv.Atoi(v)
	if err != nil || days < 0 {
		return 0, fmt.Errorf("stored key expiry %q: not a number of days", v)
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

// DNS returns the DNS configuration.
func (s *Service) DNS(ctx context.Context) (DNSConfig, error) {
	raw, err := s.store.Setting(ctx, store.SettingDNS)
	if err != nil {
		return DNSConfig{}, err
	}
	c := cloneDNS(DefaultDNS)
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return DNSConfig{}, fmt.Errorf("stored DNS settings: %w", err)
		}
	}
	return c, nil
}

// SetDNS validates, stores and applies a DNS configuration.
func (s *Service) SetDNS(ctx context.Context, c DNSConfig) (DNSConfig, error) {
	if err := c.Validate(); err != nil {
		return DNSConfig{}, err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return DNSConfig{}, err
	}
	if err := s.store.SetSetting(ctx, store.SettingDNS, string(b)); err != nil {
		return DNSConfig{}, err
	}
	s.hub.broadcast()
	return c, nil
}

func cloneDNS(c DNSConfig) DNSConfig {
	out := c
	out.Split = make([]SplitDNS, len(c.Split))
	for i, sd := range c.Split {
		out.Split[i] = SplitDNS{Domain: sd.Domain, Resolvers: slices.Clone(sd.Resolvers)}
	}
	return out
}

// autoApprove adds the node's advertised routes the policy approves to its
// approved routes, returning the (possibly updated) node.
func (s *Service) autoApprove(ctx context.Context, n store.Node, p *policy.Policy) (store.Node, error) {
	auto := p.AutoApproved(policyNode(n), n.AdvertisedRoutes)
	approved := slices.Clone(n.ApprovedRoutes)
	for _, r := range auto {
		if !slices.Contains(approved, r) {
			approved = append(approved, r)
		}
	}
	if len(approved) == len(n.ApprovedRoutes) {
		return n, nil
	}
	updated, err := s.store.SetApprovedRoutes(ctx, n.ID, approved)
	if err != nil {
		return n, err
	}
	s.log.Info("routes auto-approved", "node", n.Name, "routes", auto)
	if err := s.store.AppendAudit(ctx, store.AuditEntry{
		Actor: "policy", Action: "routes.approve", Target: n.Name, Detail: prefixList(auto),
	}); err != nil {
		s.log.Warn("audit", "err", err)
	}
	return updated, nil
}

// ApproveRoutes replaces a node's approved routes.
func (s *Service) ApproveRoutes(ctx context.Context, nodeID string, routes []netip.Prefix) (store.Node, error) {
	n, err := s.store.SetApprovedRoutes(ctx, nodeID, routes)
	if err != nil {
		return store.Node{}, err
	}
	s.hub.broadcast()
	return n, nil
}

func policyNode(n store.Node) policy.Node {
	return policy.Node{Name: n.Name, IP: n.IPv4, Tags: n.Tags, Routes: n.Routes()}
}

func policyNodes(nodes []store.Node) []policy.Node {
	out := make([]policy.Node, len(nodes))
	for i, n := range nodes {
		out[i] = policyNode(n)
	}
	return out
}

func prefixStrings(ps []netip.Prefix) []string {
	strs := make([]string, len(ps))
	for i, p := range ps {
		strs[i] = p.String()
	}
	return strs
}

func prefixList(ps []netip.Prefix) string { return strings.Join(prefixStrings(ps), ", ") }

// Compiled returns the policy compiled against the current nodes.
func (s *Service) Compiled(ctx context.Context) (*policy.Compiled, []store.Node, error) {
	p, _, err := s.Policy(ctx)
	if err != nil {
		return nil, nil, err
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, nil, err
	}
	return p.Compile(policyNodes(nodes)), nodes, nil
}

// Topology returns the latest peer paths reported by each online node.
func (s *Service) Topology() map[string][]PeerPath {
	s.ps.mu.Lock()
	defer s.ps.mu.Unlock()
	out := make(map[string][]PeerPath, len(s.ps.reports))
	for id, r := range s.ps.reports {
		if s.hub.online(id) {
			out[id] = slices.Clone(r.peers)
		}
	}
	return out
}

// setReport stores a node's peer paths, reporting whether they changed
// enough to be worth telling the UI about.
func (s *Service) setReport(nodeID string, peers []PeerPath) bool {
	s.ps.mu.Lock()
	defer s.ps.mu.Unlock()
	old, had := s.ps.reports[nodeID]
	s.ps.reports[nodeID] = statusReport{peers: peers, at: time.Now()}
	if !had || len(old.peers) != len(peers) {
		return true
	}
	for i := range peers {
		if old.peers[i].NodeID != peers[i].NodeID || old.peers[i].Path != peers[i].Path {
			return true
		}
	}
	return false
}

func (s *Service) dropReport(nodeID string) {
	s.ps.mu.Lock()
	defer s.ps.mu.Unlock()
	delete(s.ps.reports, nodeID)
}
