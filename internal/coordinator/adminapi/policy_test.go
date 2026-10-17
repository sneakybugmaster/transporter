package adminapi

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
)

func ptr[T any](v T) *T { return &v }

func (e *env) registerNodes(names ...string) []store.Node {
	e.t.Helper()
	ctx := context.Background()
	_, secret, _ := e.store.CreateAuthKey(ctx, store.AuthKeyOptions{Reusable: true})
	var out []store.Node
	for i, name := range names {
		n, _, err := e.store.RegisterNode(ctx, store.RegisterRequest{
			AuthKey: secret, WGPublicKey: [32]byte{byte(i + 1)}, Hostname: name, OS: "linux", Prefix: netip.MustParsePrefix("100.64.0.0/10"),
		})
		if err != nil {
			e.t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func TestTagsAndRoutesOnNodes(t *testing.T) {
	e := newEnv(t)
	e.setup()
	nodes := e.registerNodes("gw")
	gw := nodes[0]
	ctx := context.Background()
	if err := e.store.SetAdvertisedRoutes(ctx, gw.ID, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}); err != nil {
		t.Fatal(err)
	}

	var n Node
	r := e.do(e.c, "PATCH", "/nodes/"+gw.ID, NodeUpdate{Tags: &[]string{"tag:Router ", "tag:router", "tag:exit"}})
	e.expect(r, 200)
	r.decode(t, &n)
	if !slices.Equal(n.Tags, []string{"tag:router", "tag:exit"}) || n.Name != "gw" {
		t.Fatalf("tags = %v", n.Tags)
	}
	e.expect(e.do(e.c, "PATCH", "/nodes/"+gw.ID, NodeUpdate{Tags: &[]string{"router"}}), 400)

	r = e.do(e.c, "PATCH", "/nodes/"+gw.ID, NodeUpdate{ApprovedRoutes: &[]string{"10.0.0.9/24", "0.0.0.0/0"}})
	e.expect(r, 200)
	r.decode(t, &n)
	if !slices.Equal(n.ApprovedRoutes, []string{"10.0.0.0/24", "0.0.0.0/0"}) || !slices.Equal(n.Routes, []string{"10.0.0.0/24"}) ||
		!slices.Equal(n.AdvertisedRoutes, []string{"10.0.0.0/24"}) {
		t.Fatalf("routes = %+v", n)
	}
	e.expect(e.do(e.c, "PATCH", "/nodes/"+gw.ID, NodeUpdate{ApprovedRoutes: &[]string{"nope"}}), 400)

	var created AuthKeyCreated
	r = e.do(e.c, "POST", "/authkeys", AuthKeyCreate{Reusable: true, Tags: &[]string{"tag:ci"}})
	e.expect(r, 201)
	r.decode(t, &created)
	if !slices.Equal(created.Key.Tags, []string{"tag:ci"}) {
		t.Fatalf("key tags = %v", created.Key.Tags)
	}
	e.expect(e.do(e.c, "POST", "/authkeys", AuthKeyCreate{Tags: &[]string{"ci"}}), 400)

	var audit []AuditEntry
	e.do(e.c, "GET", "/audit?limit=3", nil).decode(t, &audit)
	if len(audit) != 3 || audit[0].Action != "authkey.create" || audit[1].Action != "node.routes" || audit[2].Action != "node.tags" ||
		audit[2].Actor != "admin" || audit[2].Target != "gw" {
		t.Fatalf("audit = %+v", audit)
	}
	var older []AuditEntry
	e.do(e.c, "GET", "/audit?before="+itoa(audit[2].Id), nil).decode(t, &older)
	if len(older) == 0 || older[0].Action != "setup.complete" {
		t.Fatalf("older audit = %+v", older)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestPolicyEndpoints(t *testing.T) {
	e := newEnv(t)
	e.setup()
	nodes := e.registerNodes("laptop", "web")
	ctx := context.Background()
	if _, err := e.store.SetNodeTags(ctx, nodes[1].ID, []string{"tag:web"}); err != nil {
		t.Fatal(err)
	}

	var p Policy
	e.do(e.c, "GET", "/policy", nil).decode(t, &p)
	if !strings.Contains(p.Policy, `"acls"`) {
		t.Fatalf("default policy = %q", p.Policy)
	}

	var pe PolicyError
	r := e.do(e.c, "PUT", "/policy", Policy{Policy: `{"acls": [{"action": "accept"}]}`})
	e.expect(r, 400)
	r.decode(t, &pe)
	if len(pe.Details) != 1 || !strings.Contains(pe.Details[0], "src and dst") {
		t.Fatalf("error = %+v", pe)
	}
	r = e.do(e.c, "PUT", "/policy", Policy{Policy: `{"acls": [], "tests": [{"src": "laptop", "accept": ["web:443"]}]}`})
	e.expect(r, 400)
	r.decode(t, &pe)
	if !strings.Contains(pe.Details[0], "should accept") {
		t.Fatalf("test failure = %+v", pe)
	}

	text := `{"acls": [{"action": "accept", "src": ["laptop"], "dst": ["tag:web:443"]}]}`
	e.expect(e.do(e.c, "PUT", "/policy", Policy{Policy: text}), 200)
	e.do(e.c, "GET", "/policy", nil).decode(t, &p)
	if p.Policy != text {
		t.Fatalf("stored policy = %q", p.Policy)
	}

	check := func(c PolicyCheck) PolicyCheckResult {
		t.Helper()
		var res PolicyCheckResult
		r := e.do(e.c, "POST", "/policy/check", c)
		e.expect(r, 200)
		r.decode(t, &res)
		return res
	}
	if res := check(PolicyCheck{Src: "laptop", Dst: "web", Port: 443}); !res.Allowed || *res.Rule != 0 || res.DstAddr != "100.64.0.2" {
		t.Fatalf("laptop -> web:443 = %+v", res)
	}
	if res := check(PolicyCheck{Src: "web", Dst: "laptop", Port: 443}); res.Allowed || res.Rule != nil {
		t.Fatalf("web -> laptop = %+v", res)
	}
	// A draft policy is checked without being saved.
	draft := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
	if res := check(PolicyCheck{Policy: &draft, Src: "web", Dst: "10.9.0.1", Port: 22}); !res.Allowed ||
		!strings.Contains(res.Reason, "no node owns") {
		t.Fatalf("draft check = %+v", res)
	}
	e.expect(e.do(e.c, "POST", "/policy/check", PolicyCheck{Src: "ghost", Dst: "web", Port: 1}), 400)

	var audit []AuditEntry
	e.do(e.c, "GET", "/audit?limit=1", nil).decode(t, &audit)
	if audit[0].Action != "policy.update" {
		t.Fatalf("audit = %+v", audit)
	}
}

func TestDNSAndTopology(t *testing.T) {
	e := newEnv(t)
	e.setup()

	var c DNSConfig
	e.do(e.c, "GET", "/dns", nil).decode(t, &c)
	if !c.MagicDNS || c.Domain != "mesh.internal" || c.Split == nil {
		t.Fatalf("default DNS = %+v", c)
	}
	e.expect(e.do(e.c, "PUT", "/dns", DNSConfig{Domain: "not a domain", Split: []SplitDNS{}}), 400)
	r := e.do(e.c, "PUT", "/dns", DNSConfig{MagicDNS: false, Domain: "Corp.Mesh", Split: []SplitDNS{{Domain: "lan", Resolvers: []string{"10.0.0.1"}}}})
	e.expect(r, 200)
	r.decode(t, &c)
	if c.Domain != "corp.mesh" || c.MagicDNS || len(c.Split) != 1 {
		t.Fatalf("saved DNS = %+v", c)
	}

	var topo Topology
	e.do(e.c, "GET", "/topology", nil).decode(t, &topo)
	if topo.Links == nil || len(topo.Links) != 0 {
		t.Fatalf("topology = %+v", topo)
	}
}
