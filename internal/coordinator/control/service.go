// Package control implements the agent-facing control plane.
package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/sneakybugmaster/transporter/internal/coordinator/ipam"
	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
	"github.com/sneakybugmaster/transporter/internal/filter"
	"github.com/sneakybugmaster/transporter/internal/metrics"
	controlv1 "github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1"
	"github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1/controlv1connect"
)

const (
	maxEndpoints = 16
	maxRoutes    = 64
	maxReport    = 4096
	// heartbeat is how often an unchanged netmap is resent; it keeps idle
	// connections (and any proxies in between) alive and refreshes last-seen.
	heartbeat = 30 * time.Second
)

// Service implements controlv1connect.ControlServiceHandler.
type Service struct {
	store     *store.Store
	prefix    netip.Prefix
	opts      Options
	log       *slog.Logger
	hub       *hub
	heartbeat time.Duration
	ps        policyState
	snaps     snapshotCache
}

// Options describes the NAT-traversal services the coordinator offers, which
// are announced to nodes in every netmap.
type Options struct {
	// STUNPort is the UDP port of the STUN server; 0 if disabled.
	STUNPort uint16
	// RelayEnabled reports whether the packet relay is served.
	RelayEnabled bool
}

var _ controlv1connect.ControlServiceHandler = (*Service)(nil)

// NewService returns a control service allocating addresses from prefix.
func NewService(s *store.Store, prefix netip.Prefix, opts Options, log *slog.Logger) *Service {
	return &Service{
		store: s, prefix: prefix.Masked(), opts: opts, log: log, hub: newHub(), heartbeat: heartbeat,
		ps: policyState{reports: map[string]statusReport{}},
	}
}

// Handler returns the mount path and HTTP handler for the service.
func (s *Service) Handler() (string, http.Handler) {
	return controlv1connect.NewControlServiceHandler(s, connect.WithReadMaxBytes(1<<20))
}

// Notify tells every connected node to refresh its netmap, e.g. after an
// administrator changed something.
func (s *Service) Notify() { s.hub.broadcast() }

// Subscribe returns a channel that receives a value (coalesced) whenever the
// mesh changes, and a function to stop listening.
func (s *Service) Subscribe() (<-chan struct{}, func()) { return s.hub.subscribe() }

// Options returns the NAT-traversal options announced to nodes.
func (s *Service) Options() Options { return s.opts }

// Prefix returns the mesh network prefix.
func (s *Service) Prefix() netip.Prefix { return s.prefix }

// Online reports whether the node currently has an open control stream.
func (s *Service) Online(nodeID string) bool { return s.hub.online(nodeID) }

func (s *Service) Register(ctx context.Context, req *connect.Request[controlv1.RegisterRequest]) (*connect.Response[controlv1.RegisterResponse], error) {
	m := req.Msg
	if len(m.GetWireguardPublicKey()) != 32 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("wireguard_public_key must be 32 bytes"))
	}
	hostname := strings.TrimSpace(m.GetHostname())
	if hostname == "" {
		hostname = "node"
	}
	if len(hostname) > 255 || len(m.GetOs()) > 64 {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("hostname or os too long"))
	}

	var key [32]byte
	copy(key[:], m.GetWireguardPublicKey())
	keyExpiry, err := s.KeyExpiry(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	node, token, err := s.store.RegisterNode(ctx, store.RegisterRequest{
		AuthKey:     m.GetAuthKey(),
		WGPublicKey: key,
		Hostname:    hostname,
		OS:          m.GetOs(),
		Prefix:      s.prefix,
		KeyExpiry:   keyExpiry,
	})
	switch {
	case errors.Is(err, store.ErrInvalidAuthKey):
		metrics.Registrations.WithLabelValues("invalid_key").Inc()
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, ipam.ErrExhausted):
		metrics.Registrations.WithLabelValues("exhausted").Inc()
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	case err != nil:
		metrics.Registrations.WithLabelValues("error").Inc()
		s.log.Error("register node", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("registration failed"))
	}
	metrics.Registrations.WithLabelValues("ok").Inc()

	s.log.Info("node registered", "node", node.Name, "id", node.ID, "ip", node.IPv4, "peer", req.Peer().Addr)
	s.hub.broadcast()
	return connect.NewResponse(&controlv1.RegisterResponse{
		Node:      s.nodeProto(node),
		NodeToken: token,
	}), nil
}

func (s *Service) WatchNetmap(ctx context.Context, req *connect.Request[controlv1.WatchNetmapRequest], stream *connect.ServerStream[controlv1.WatchNetmapResponse]) error {
	node, err := s.authenticate(ctx, req.Header())
	if err != nil {
		return err
	}
	endpoints, err := parseEndpoints(req.Msg.GetEndpoints())
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	routes, err := s.parseRoutes(req.Msg.GetAdvertisedRoutes())
	if err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err)
	}
	if err := s.store.UpdateNodeEndpoints(ctx, node.ID, endpoints); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if !slices.Equal(routes, node.AdvertisedRoutes) {
		if err := s.store.SetAdvertisedRoutes(ctx, node.ID, routes); err != nil {
			return connect.NewError(connect.CodeInternal, err)
		}
		node.AdvertisedRoutes = routes
		if len(routes) > 0 {
			s.log.Info("node advertises routes", "node", node.Name, "routes", routes)
		}
	}
	p, _, err := s.Policy(ctx)
	if err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}
	if _, err := s.autoApprove(ctx, node, p); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	w := s.hub.add(node.ID)
	metrics.ControlStreams.Inc()
	defer metrics.ControlStreams.Dec()
	log := s.log.With("node", node.Name, "id", node.ID)
	log.Info("node connected", "endpoints", endpoints)
	s.hub.broadcast() // peers learn this node is online with fresh endpoints
	defer func() {
		s.hub.remove(w)
		if !s.hub.online(node.ID) {
			s.dropReport(node.ID)
		}
		// The request context is done by now; use a fresh one for cleanup.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.store.TouchNode(cleanupCtx, node.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			log.Warn("touch node", "err", err)
		}
		s.hub.broadcast()
		log.Info("node disconnected")
	}()

	ticker := time.NewTicker(s.heartbeat)
	defer ticker.Stop()
	var last *controlv1.WatchNetmapResponse
	heartbeat := false
	for {
		nm, err := s.netmap(ctx, node.ID)
		if err != nil {
			return err
		}
		// Send only what changed this node's view; most broadcasts concern
		// nodes it cannot see. Heartbeats without changes are a bare
		// keepalive rather than the whole netmap again.
		switch {
		case last == nil || !proto.Equal(nm, last):
			err = stream.Send(nm)
			last = nm
			metrics.NetmapsSent.Inc()
			metrics.NetmapBytes.Add(float64(proto.Size(nm)))
		case heartbeat:
			err = stream.Send(&controlv1.WatchNetmapResponse{KeepAlive: true})
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-w.notify:
			heartbeat = false
		case <-ticker.C:
			heartbeat = true
			if err := s.store.TouchNode(ctx, node.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				log.Warn("touch node", "err", err)
			}
		}
	}
}

func (s *Service) UpdateEndpoints(ctx context.Context, req *connect.Request[controlv1.UpdateEndpointsRequest]) (*connect.Response[controlv1.UpdateEndpointsResponse], error) {
	node, err := s.authenticate(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	endpoints, err := parseEndpoints(req.Msg.GetEndpoints())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	if !slices.Equal(endpoints, node.Endpoints) {
		if err := s.store.UpdateNodeEndpoints(ctx, node.ID, endpoints); err != nil {
			return nil, connect.NewError(connect.CodeInternal, err)
		}
		s.log.Info("node endpoints changed", "node", node.Name, "endpoints", endpoints)
		s.hub.broadcast()
	}
	return connect.NewResponse(&controlv1.UpdateEndpointsResponse{}), nil
}

func (s *Service) ReportStatus(ctx context.Context, req *connect.Request[controlv1.ReportStatusRequest]) (*connect.Response[controlv1.ReportStatusResponse], error) {
	node, err := s.authenticate(ctx, req.Header())
	if err != nil {
		return nil, err
	}
	in := req.Msg.GetPeers()
	if len(in) > maxReport {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("too many peers"))
	}
	peers := make([]PeerPath, 0, len(in))
	for _, p := range in {
		if p.GetPath() != "direct" && p.GetPath() != "relay" {
			continue
		}
		peers = append(peers, PeerPath{NodeID: p.GetNodeId(), Path: p.GetPath(), LatencyMs: p.GetLatencyMs()})
	}
	slices.SortFunc(peers, func(a, b PeerPath) int { return strings.Compare(a.NodeID, b.NodeID) })
	if s.setReport(node.ID, peers) {
		s.hub.notifyAdmins()
	}
	return connect.NewResponse(&controlv1.ReportStatusResponse{}), nil
}

// parseRoutes validates advertised routes: IPv4 prefixes outside the mesh
// (except 0.0.0.0/0, which offers an exit node).
func (s *Service) parseRoutes(in []string) ([]netip.Prefix, error) {
	if len(in) > maxRoutes {
		return nil, fmt.Errorf("too many routes (max %d)", maxRoutes)
	}
	var out []netip.Prefix
	for _, r := range in {
		p, err := netip.ParsePrefix(r)
		if err != nil || !p.Addr().Is4() {
			return nil, fmt.Errorf("invalid route %q", r)
		}
		p = p.Masked()
		if p.Bits() > 0 && p.Overlaps(s.prefix) {
			return nil, fmt.Errorf("route %s overlaps the mesh network %s", p, s.prefix)
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr())*64 + a.Bits() - b.Bits() })
	return out, nil
}

func (s *Service) authenticate(ctx context.Context, h http.Header) (store.Node, error) {
	token, ok := strings.CutPrefix(h.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		return store.Node{}, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer token"))
	}
	node, err := s.store.NodeByToken(ctx, token)
	if errors.Is(err, store.ErrNotFound) {
		return store.Node{}, connect.NewError(connect.CodeUnauthenticated, errors.New("unknown node token"))
	}
	if err != nil {
		return store.Node{}, connect.NewError(connect.CodeInternal, err)
	}
	if node.Expired(time.Now()) {
		return store.Node{}, errKeyExpired
	}
	return node, nil
}

// errKeyExpired tells an agent to re-authenticate with an auth key.
var errKeyExpired = connect.NewError(connect.CodeUnauthenticated, errors.New("node key expired: re-authenticate with an auth key"))

// netmap builds the view of the mesh for one node: the peers the policy
// lets it talk to (in either direction) and the traffic it must accept.
func (s *Service) netmap(ctx context.Context, nodeID string) (*controlv1.WatchNetmapResponse, error) {
	sn, err := s.snapshot(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	i, ok := sn.index[nodeID]
	if !ok {
		// Deleted while connected: end the stream; the token no longer works.
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("node was removed"))
	}
	now := time.Now()
	if sn.nodes[i].Expired(now) {
		return nil, errKeyExpired
	}
	// The snapshot's messages are shared between streams and never modified.
	resp := &controlv1.WatchNetmapResponse{
		NetworkPrefix: s.prefix.String(),
		StunPort:      uint32(s.opts.STUNPort),
		RelayEnabled:  s.opts.RelayEnabled,
		Dns:           sn.dns,
		Self:          sn.protos[i],
	}
	me := sn.pnodes[i]
	for j, n := range sn.pnodes {
		if j != i && !sn.nodes[j].Expired(now) && sn.compiled.Visible(me, n) {
			resp.Peers = append(resp.Peers, sn.protos[j])
		}
	}
	for _, r := range sn.compiled.FilterFor(me) {
		resp.PacketFilter = append(resp.PacketFilter, filterRuleProto(r))
	}
	return resp, nil
}

func filterRuleProto(r filter.Rule) *controlv1.FilterRule {
	out := &controlv1.FilterRule{}
	for _, p := range r.Srcs {
		out.SrcPrefixes = append(out.SrcPrefixes, p.String())
	}
	for _, d := range r.Dsts {
		out.Destinations = append(out.Destinations, &controlv1.FilterDestination{
			Prefix: d.Prefix.String(), FirstPort: uint32(d.Ports.First), LastPort: uint32(d.Ports.Last),
		})
	}
	for _, p := range r.Protos {
		out.Protocols = append(out.Protocols, uint32(p))
	}
	return out
}

func dnsProto(c DNSConfig) *controlv1.DnsConfig {
	out := &controlv1.DnsConfig{MagicDns: c.MagicDNS, Domain: c.Domain}
	for _, sd := range c.Split {
		out.SplitDns = append(out.SplitDns, &controlv1.SplitDns{Domain: sd.Domain, Resolvers: sd.Resolvers})
	}
	return out
}

func (s *Service) nodeProto(n store.Node) *controlv1.Node {
	return &controlv1.Node{
		Id:                 n.ID,
		Name:               n.Name,
		Hostname:           n.Hostname,
		Os:                 n.OS,
		WireguardPublicKey: n.WGPublicKey[:],
		Addresses:          []string{netip.PrefixFrom(n.IPv4, 32).String()},
		Endpoints:          n.Endpoints,
		Online:             s.hub.online(n.ID),
		LastSeen:           timestamppb.New(n.LastSeen),
		Tags:               n.Tags,
		Routes:             prefixStrings(n.Routes()),
	}
}

func parseEndpoints(in []string) ([]string, error) {
	if len(in) > maxEndpoints {
		return nil, fmt.Errorf("too many endpoints (max %d)", maxEndpoints)
	}
	out := make([]string, 0, len(in))
	for _, e := range in {
		ap, err := netip.ParseAddrPort(e)
		if err != nil || !ap.IsValid() || ap.Port() == 0 || ap.Addr().IsUnspecified() {
			return nil, fmt.Errorf("invalid endpoint %q", e)
		}
		out = appendUnique(out, ap.String())
	}
	return out, nil
}

func appendUnique(dst []string, items ...string) []string {
	for _, it := range items {
		dup := false
		for _, d := range dst {
			if d == it {
				dup = true
				break
			}
		}
		if !dup {
			dst = append(dst, it)
		}
	}
	return dst
}
