package control

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"

	controlv1 "github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1"
)

func (e *env) tag(t *testing.T, n *controlv1.Node, tags ...string) {
	t.Helper()
	if _, err := e.store.SetNodeTags(context.Background(), n.GetId(), tags); err != nil {
		t.Fatal(err)
	}
}

func peerNames(nm *controlv1.WatchNetmapResponse) []string {
	var out []string
	for _, p := range nm.GetPeers() {
		out = append(out, p.GetName())
	}
	slices.Sort(out)
	return out
}

const devToWeb = `{
  "acls": [{"action": "accept", "src": ["tag:dev"], "dst": ["tag:web:22"], "proto": "tcp"}],
  "tests": [{"src": "laptop", "accept": ["web:22"], "deny": ["db:22"]}],
}`

func TestPolicyShapesNetmaps(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	laptop, laptopTok := e.register(t, 1, "laptop")
	web, webTok := e.register(t, 2, "web")
	_, dbTok := e.register(t, 3, "db")
	e.tag(t, laptop, "tag:dev")
	e.tag(t, web, "tag:web")

	wl, ww, wd := e.watch(t, laptopTok), e.watch(t, webTok), e.watch(t, dbTok)
	// Default policy: everyone sees everyone and accepts everything.
	nm := wd.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return len(nm.GetPeers()) == 2 })
	if len(nm.GetPacketFilter()) != 1 || nm.GetPacketFilter()[0].GetSrcPrefixes()[0] != "0.0.0.0/0" {
		t.Fatalf("default filter = %v", nm.GetPacketFilter())
	}

	if _, err := e.svc.SetPolicy(ctx, devToWeb); err != nil {
		t.Fatal(err)
	}
	nm = wl.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return len(nm.GetPeers()) == 1 })
	if got := peerNames(nm); !slices.Equal(got, []string{"web"}) {
		t.Fatalf("laptop sees %v", got)
	}
	if len(nm.GetPacketFilter()) != 0 {
		t.Fatalf("laptop accepts %v, want nothing", nm.GetPacketFilter())
	}
	nm = ww.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return len(nm.GetPeers()) == 1 })
	if got := peerNames(nm); !slices.Equal(got, []string{"laptop"}) {
		t.Fatalf("web sees %v", got)
	}
	f := nm.GetPacketFilter()
	if len(f) != 1 || !slices.Equal(f[0].GetSrcPrefixes(), []string{"100.64.0.1/32"}) ||
		f[0].GetDestinations()[0].GetPrefix() != "100.64.0.2/32" || f[0].GetDestinations()[0].GetFirstPort() != 22 ||
		!slices.Equal(f[0].GetProtocols(), []uint32{6}) {
		t.Fatalf("web filter = %v", f)
	}
	wd.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return len(nm.GetPeers()) == 0 })

	// Retagging a node takes effect on the next netmap.
	e.tag(t, laptop)
	e.svc.Notify()
	wl.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return len(nm.GetPeers()) == 0 })
}

func TestSetPolicyRejects(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	laptop, _ := e.register(t, 1, "laptop")
	e.register(t, 2, "web")
	e.register(t, 3, "db")
	e.tag(t, laptop, "tag:dev")

	var pe *PolicyError
	if _, err := e.svc.SetPolicy(ctx, `{"acls": [}`); !errors.As(err, &pe) {
		t.Fatalf("syntax error: %v", err)
	}
	// web is not tagged yet, so the test "laptop may reach web:22" fails.
	_, err := e.svc.SetPolicy(ctx, devToWeb)
	if !errors.As(err, &pe) || !strings.Contains(err.Error(), "should accept") {
		t.Fatalf("failing test: %v", err)
	}
	if _, text, _ := e.svc.Policy(ctx); !strings.Contains(text, `"dst": ["*:*"]`) {
		t.Fatal("rejected policy was stored")
	}
}

func TestRoutesAndApproval(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	gw, gwTok := e.register(t, 1, "gw")
	_, clientTok := e.register(t, 2, "client")
	wc := e.watch(t, clientTok)

	bad := e.watchReq(t, gwTok, &controlv1.WatchNetmapRequest{AdvertisedRoutes: []string{"100.64.5.0/24"}})
	if err := <-bad.errc; connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("route inside the mesh: %v", err)
	}

	e.watchReq(t, gwTok, &controlv1.WatchNetmapRequest{AdvertisedRoutes: []string{"10.1.0.7/24", "0.0.0.0/0"}})
	nm := wc.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return peerNamed(nm, "gw").GetOnline() })
	if r := peerNamed(nm, "gw").GetRoutes(); len(r) != 0 {
		t.Fatalf("unapproved routes visible: %v", r)
	}
	n, _ := e.store.NodeByID(ctx, gw.GetId())
	want := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("10.1.0.0/24")}
	if !slices.Equal(n.AdvertisedRoutes, want) {
		t.Fatalf("advertised = %v, want %v (masked, sorted)", n.AdvertisedRoutes, want)
	}

	if _, err := e.svc.ApproveRoutes(ctx, gw.GetId(), want[1:]); err != nil {
		t.Fatal(err)
	}
	nm = wc.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return len(peerNamed(nm, "gw").GetRoutes()) == 1 })
	if r := peerNamed(nm, "gw").GetRoutes(); r[0] != "10.1.0.0/24" {
		t.Fatalf("routes = %v", r)
	}

	// autoApprovers approve the exit node as soon as the policy allows it.
	e.tag(t, gw, "tag:exit")
	if _, err := e.svc.SetPolicy(ctx, `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		"autoApprovers": {"exitNode": ["tag:exit"]}}`); err != nil {
		t.Fatal(err)
	}
	wc.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return len(peerNamed(nm, "gw").GetRoutes()) == 2 })
	audit, _ := e.store.ListAudit(ctx, 10, 0)
	if len(audit) == 0 || audit[0].Actor != "policy" || audit[0].Detail != "0.0.0.0/0" {
		t.Fatalf("audit = %+v", audit)
	}
}

func TestDNSConfig(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, tok := e.register(t, 1, "alpha")
	w := e.watch(t, tok)
	nm := w.next(t, func(*controlv1.WatchNetmapResponse) bool { return true })
	if d := nm.GetDns(); !d.GetMagicDns() || d.GetDomain() != "mesh.internal" {
		t.Fatalf("default DNS = %v", d)
	}

	for _, bad := range []DNSConfig{
		{Domain: "bad domain"},
		{Domain: "mesh.internal", Split: []SplitDNS{{Domain: "corp.example", Resolvers: []string{"dns.corp"}}}},
		{Domain: "mesh.internal", Split: []SplitDNS{{Domain: "internal", Resolvers: []string{"10.0.0.53"}}}},
		{Domain: "mesh.internal", Split: []SplitDNS{{Domain: "corp.example"}}},
	} {
		if _, err := e.svc.SetDNS(ctx, bad); err == nil {
			t.Errorf("SetDNS(%+v) accepted", bad)
		}
	}
	got, err := e.svc.SetDNS(ctx, DNSConfig{MagicDNS: true, Domain: " Ts.Example. ",
		Split: []SplitDNS{{Domain: "Corp.Example", Resolvers: []string{"10.0.0.53", "10.0.0.54:5353"}}}})
	if err != nil || got.Domain != "ts.example" || got.Split[0].Domain != "corp.example" {
		t.Fatalf("SetDNS = %+v, %v", got, err)
	}
	nm = w.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return nm.GetDns().GetDomain() == "ts.example" })
	if sd := nm.GetDns().GetSplitDns(); len(sd) != 1 || !slices.Equal(sd[0].GetResolvers(), []string{"10.0.0.53", "10.0.0.54:5353"}) {
		t.Fatalf("split DNS = %v", sd)
	}
}

func TestReportStatus(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, tok := e.register(t, 1, "alpha")
	b, _ := e.register(t, 2, "bravo")
	w := e.watch(t, tok)
	w.next(t, func(*controlv1.WatchNetmapResponse) bool { return true })
	events, stop := e.svc.Subscribe()
	defer stop()
	for len(events) > 0 {
		<-events
	}

	req := connect.NewRequest(&controlv1.ReportStatusRequest{Peers: []*controlv1.PeerPath{
		{NodeId: b.GetId(), Path: "direct", LatencyMs: 1.5},
		{NodeId: "x", Path: "bogus"},
	}})
	req.Header().Set("Authorization", "Bearer "+tok)
	if _, err := e.client.ReportStatus(ctx, req); err != nil {
		t.Fatal(err)
	}
	topo := e.svc.Topology()
	if p := topo[a.GetId()]; len(p) != 1 || p[0].NodeID != b.GetId() || p[0].LatencyMs != 1.5 {
		t.Fatalf("topology = %+v", topo)
	}
	select {
	case <-events:
	default:
		t.Fatal("admins not notified of a new report")
	}

	w.cancel()
	<-w.errc
	waitFor(t, func() bool { return len(e.svc.Topology()) == 0 })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for range 500 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
