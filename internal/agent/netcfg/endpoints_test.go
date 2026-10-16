package netcfg

import (
	"net/netip"
	"testing"
)

func TestLocalEndpoints(t *testing.T) {
	eps, err := LocalEndpoints(41641, netip.MustParsePrefix("100.64.0.0/10"))
	if err != nil {
		t.Fatal(err)
	}
	seenV6 := false
	for _, ep := range eps {
		if ep.Port() != 41641 || !usable(ep.Addr()) || ep.Addr().IsLoopback() {
			t.Errorf("unexpected endpoint %s", ep)
		}
		if ep.Addr().Is6() {
			seenV6 = true
		} else if seenV6 {
			t.Errorf("IPv4 endpoint %s listed after IPv6", ep)
		}
	}
}

func TestUsable(t *testing.T) {
	for s, want := range map[string]bool{
		"192.168.1.10": true,
		"203.0.113.5":  true,
		"2001:db8::1":  true,
		"127.0.0.1":    false,
		"169.254.1.1":  false,
		"fe80::1":      false,
		"0.0.0.0":      false,
		"224.0.0.1":    false,
	} {
		if got := usable(netip.MustParseAddr(s)); got != want {
			t.Errorf("usable(%s) = %v, want %v", s, got, want)
		}
	}
}
