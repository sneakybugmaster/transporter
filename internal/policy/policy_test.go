package policy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/sneakybugmaster/transporter/internal/filter"
)

var (
	dev    = Node{Name: "laptop", IP: netip.MustParseAddr("100.64.0.1"), Tags: []string{"tag:dev"}}
	server = Node{Name: "web", IP: netip.MustParseAddr("100.64.0.2"), Tags: []string{"tag:server"}}
	db     = Node{Name: "db", IP: netip.MustParseAddr("100.64.0.3"), Tags: []string{"tag:server", "tag:db"}}
	router = Node{Name: "gw", IP: netip.MustParseAddr("100.64.0.4"), Tags: []string{"tag:router"},
		Routes: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")}}
	nodes = []Node{dev, server, db, router}
)

const sample = `{
  // comments and trailing commas are fine
  "hosts": {"office": "10.1.0.0/24", "printer": "10.1.0.9"},
  "acls": [
    {"action": "accept", "src": ["tag:dev"], "dst": ["tag:server:22,80-81", "office:*"]},
    {"action": "accept", "src": ["web"], "dst": ["db:5432"], "proto": "tcp"},
  ],
  "autoApprovers": {"routes": {"10.0.0.0/8": ["tag:router"]}, "exitNode": ["gw"]},
  "tests": [
    {"src": "tag:dev", "accept": ["web:22", "printer:631"], "deny": ["web:443", "db:5432"]},
    {"src": "web", "accept": ["db:5432"], "deny": ["laptop:22"]},
  ],
}`

func mustParse(t *testing.T, s string) *Policy {
	t.Helper()
	p, err := Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCompileAndAllow(t *testing.T) {
	c := mustParse(t, sample).Compile(nodes)
	tests := []struct {
		src, dst string
		proto    uint8
		port     uint16
		want     bool
	}{
		{"100.64.0.1", "100.64.0.2", filter.ProtoTCP, 22, true},
		{"100.64.0.1", "100.64.0.3", filter.ProtoTCP, 81, true}, // db is a server too
		{"100.64.0.1", "100.64.0.2", filter.ProtoTCP, 443, false},
		{"100.64.0.1", "10.1.0.50", filter.ProtoUDP, 53, true},
		{"100.64.0.2", "100.64.0.3", filter.ProtoTCP, 5432, true},
		{"100.64.0.2", "100.64.0.3", filter.ProtoUDP, 5432, false},
		{"100.64.0.3", "100.64.0.2", filter.ProtoTCP, 5432, false},
		{"100.64.0.2", "100.64.0.1", filter.ProtoTCP, 22, false},
	}
	for _, tt := range tests {
		got, _ := c.Allowed(netip.MustParseAddr(tt.src), netip.MustParseAddr(tt.dst), tt.proto, tt.port)
		if got != tt.want {
			t.Errorf("%s -> %s %d/%d: allowed = %v, want %v", tt.src, tt.dst, tt.proto, tt.port, got, tt.want)
		}
	}
}

func TestVisibility(t *testing.T) {
	c := mustParse(t, sample).Compile(nodes)
	if !c.Visible(dev, server) || !c.Visible(server, dev) {
		t.Error("dev and server should see each other (dev connects to server)")
	}
	if !c.Visible(dev, router) {
		t.Error("dev should see the router of the office LAN it may reach")
	}
	if c.Visible(server, router) {
		t.Error("server and router have no rule between them")
	}
	if !c.CanReach(dev, router) || c.CanReach(router, dev) {
		t.Error("reachability is directional")
	}
}

func TestFilterFor(t *testing.T) {
	c := mustParse(t, sample).Compile(nodes)
	r := c.FilterFor(router)
	if len(r) != 1 {
		t.Fatalf("router rules = %+v, want the office rule only", r)
	}
	for _, d := range r[0].Dsts {
		if d.Prefix != netip.MustParsePrefix("10.1.0.0/24") {
			t.Errorf("router rule destination %v outside what it delivers", d.Prefix)
		}
	}
	// db gets both rules, narrowed to its own address.
	r = c.FilterFor(db)
	if len(r) != 2 {
		t.Fatalf("db rules = %+v", r)
	}
	for _, rule := range r {
		for _, d := range rule.Dsts {
			if d.Prefix != netip.MustParsePrefix("100.64.0.3/32") {
				t.Errorf("db rule destination %v", d.Prefix)
			}
		}
	}
	// "*" destinations narrow to the node's own address.
	all := mustParse(t, Default).Compile(nodes)
	r = all.FilterFor(dev)
	if len(r) != 1 || len(r[0].Dsts) != 1 || r[0].Dsts[0].Prefix != netip.MustParsePrefix("100.64.0.1/32") {
		t.Fatalf("default policy rules for dev = %+v", r)
	}
}

func TestDefaultAllowsEverything(t *testing.T) {
	c := mustParse(t, Default).Compile(nodes)
	for _, a := range nodes {
		for _, b := range nodes {
			if a.Name != b.Name && !c.Visible(a, b) {
				t.Errorf("%s cannot see %s under the default policy", a.Name, b.Name)
			}
		}
	}
	if ok, _ := c.Allowed(dev.IP, netip.MustParseAddr("10.1.0.7"), filter.ProtoTCP, 1); !ok {
		t.Error("default policy blocks routes")
	}
}

func TestAutoApprove(t *testing.T) {
	p := mustParse(t, sample)
	adv := []netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("0.0.0.0/0"),
	}
	got := p.AutoApproved(router, adv)
	if len(got) != 2 || got[0] != adv[0] || got[1] != adv[2] {
		t.Errorf("router auto-approved %v", got)
	}
	if got := p.AutoApproved(dev, adv); len(got) != 0 {
		t.Errorf("dev auto-approved %v", got)
	}
}

func TestRunTests(t *testing.T) {
	if errs := mustParse(t, sample).RunTests(nodes); len(errs) != 0 {
		t.Fatalf("sample tests failed: %v", errs)
	}
	bad := strings.Replace(sample, `"deny": ["web:443", "db:5432"]`, `"deny": ["web:22"]`, 1)
	errs := mustParse(t, bad).RunTests(nodes)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "should deny") {
		t.Fatalf("errs = %v", errs)
	}
}

func TestParseErrors(t *testing.T) {
	tests := map[string]string{
		`{"acls": [`:  "syntax",
		`{"acl": []}`: "unknown field",
		`{"acls": [{"action": "drop", "src": ["*"], "dst": ["*:*"]}]}`:                 "action",
		`{"acls": [{"action": "accept", "src": ["*"], "dst": ["web"]}]}`:               "needs ports",
		`{"acls": [{"action": "accept", "src": ["*"], "dst": ["web:http"]}]}`:          "bad port",
		`{"acls": [{"action": "accept", "src": ["*"], "dst": ["web:90-80"]}]}`:         "bad port range",
		`{"acls": [{"action": "accept", "src": ["tag:Bad"], "dst": ["*:*"]}]}`:         "invalid tag",
		`{"acls": [{"action": "accept", "src": ["Web Server"], "dst": ["*:*"]}]}`:      "not a tag",
		`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"], "proto": "x"}]}`: "proto",
		`{"hosts": {"x": "300.1.1.1"}, "acls": []}`:                                    "invalid IPv4",
		`{"acls": [], "tests": [{"src": "*", "accept": ["web"]}]}`:                     "needs ports",
	}
	for in, want := range tests {
		_, err := Parse([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%s) = %v, want error containing %q", in, err, want)
		}
	}
}
