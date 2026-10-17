package policy

import (
	"net/netip"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add(sample)
	f.Add(Default)
	f.Add(`{"acls": [{"action": "accept", "src": ["tag:a"], "dst": ["10.0.0.0/8:1-65535,22"]}]}`)
	f.Fuzz(func(t *testing.T, text string) {
		p, err := Parse([]byte(text))
		if err != nil {
			return
		}
		// Anything that parses must compile and evaluate without trouble.
		c := p.Compile(nodes)
		for _, n := range nodes {
			_ = c.FilterFor(n)
			_ = c.Visible(n, dev)
		}
		_, _ = c.Allowed(dev.IP, netip.MustParseAddr("10.1.0.1"), 6, 22)
		_ = p.AutoApproved(router, router.Routes)
		_ = p.RunTests(nodes)
	})
}
