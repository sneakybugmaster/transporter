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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/sneakybugmaster/transporter/internal/coordinator/ipam"
	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
	controlv1 "github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1"
	"github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1/controlv1connect"
)

const (
	maxEndpoints = 16
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
	return &Service{store: s, prefix: prefix.Masked(), opts: opts, log: log, hub: newHub(), heartbeat: heartbeat}
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
	node, token, err := s.store.RegisterNode(ctx, store.RegisterRequest{
		AuthKey:     m.GetAuthKey(),
		WGPublicKey: key,
		Hostname:    hostname,
		OS:          m.GetOs(),
		Prefix:      s.prefix,
	})
	switch {
	case errors.Is(err, store.ErrInvalidAuthKey):
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	case errors.Is(err, ipam.ErrExhausted):
		return nil, connect.NewError(connect.CodeResourceExhausted, err)
	case err != nil:
		s.log.Error("register node", "err", err)
		return nil, connect.NewError(connect.CodeInternal, errors.New("registration failed"))
	}

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
	if err := s.store.UpdateNodeEndpoints(ctx, node.ID, endpoints); err != nil {
		return connect.NewError(connect.CodeInternal, err)
	}

	w := s.hub.add(node.ID)
	log := s.log.With("node", node.Name, "id", node.ID)
	log.Info("node connected", "endpoints", endpoints)
	s.hub.broadcast() // peers learn this node is online with fresh endpoints
	defer func() {
		s.hub.remove(w)
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
	for {
		nm, err := s.netmap(ctx, node.ID)
		if err != nil {
			return err
		}
		if err := stream.Send(nm); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-w.notify:
		case <-ticker.C:
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
	return node, nil
}

// netmap builds the view of the mesh for one node.
func (s *Service) netmap(ctx context.Context, nodeID string) (*controlv1.WatchNetmapResponse, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	resp := &controlv1.WatchNetmapResponse{
		NetworkPrefix: s.prefix.String(),
		StunPort:      uint32(s.opts.STUNPort),
		RelayEnabled:  s.opts.RelayEnabled,
	}
	for _, n := range nodes {
		if n.ID == nodeID {
			resp.Self = s.nodeProto(n)
		} else {
			resp.Peers = append(resp.Peers, s.nodeProto(n))
		}
	}
	if resp.Self == nil {
		// Deleted while connected: end the stream; the token no longer works.
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("node was removed"))
	}
	return resp, nil
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
