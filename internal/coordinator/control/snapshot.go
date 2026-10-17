package control

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
	"github.com/sneakybugmaster/transporter/internal/metrics"
	"github.com/sneakybugmaster/transporter/internal/policy"
	controlv1 "github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1"
)

// maxSnapshotAge bounds how stale a snapshot may get without a broadcast,
// e.g. after changes made with the coordinator's CLI, which writes the
// database directly.
const maxSnapshotAge = 25 * time.Second

// snapshot is the mesh as every node's netmap is built from it: computed
// once per change instead of once per node, which keeps a broadcast to N
// nodes at O(N²) cheap checks rather than O(N²) database rows and policy
// compilations.
type snapshot struct {
	gen      uint64
	built    time.Time
	nodes    []store.Node
	pnodes   []policy.Node
	protos   []*controlv1.Node // nodeProto of nodes[i], shared read-only
	index    map[string]int    // node ID -> position
	compiled *policy.Compiled
	dns      *controlv1.DnsConfig
}

type snapshotCache struct {
	mu   sync.Mutex
	snap *snapshot
}

// snapshot returns the current snapshot, rebuilding it after a broadcast or
// when it is too old.
func (s *Service) snapshot(ctx context.Context) (*snapshot, error) {
	s.snaps.mu.Lock()
	defer s.snaps.mu.Unlock()
	gen := s.hub.generation()
	if sn := s.snaps.snap; sn != nil && sn.gen == gen && time.Since(sn.built) < maxSnapshotAge {
		return sn, nil
	}
	// Read the generation before the data: a broadcast that races with the
	// reads leaves a stale generation, and the next call rebuilds.
	defer prometheus.NewTimer(metrics.SnapshotBuild).ObserveDuration()
	p, _, err := s.Policy(ctx)
	if err != nil {
		return nil, err
	}
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	dns, err := s.DNS(ctx)
	if err != nil {
		return nil, err
	}
	sn := &snapshot{
		gen:    gen,
		built:  time.Now(),
		nodes:  nodes,
		pnodes: policyNodes(nodes),
		protos: make([]*controlv1.Node, len(nodes)),
		index:  make(map[string]int, len(nodes)),
		dns:    dnsProto(dns),
	}
	for i, n := range nodes {
		sn.protos[i] = s.nodeProto(n)
		sn.index[n.ID] = i
	}
	sn.compiled = p.Compile(sn.pnodes)
	s.snaps.snap = sn
	return sn, nil
}
