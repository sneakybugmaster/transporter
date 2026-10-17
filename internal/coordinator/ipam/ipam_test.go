package ipam

import (
	"errors"
	"net/netip"
	"testing"
)

func TestAllocate(t *testing.T) {
	p := netip.MustParsePrefix("100.64.0.0/10")
	used := map[netip.Addr]bool{}
	isUsed := func(a netip.Addr) bool { return used[a] }

	for _, want := range []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"} {
		got, err := Allocate(p, isUsed)
		if err != nil || got.String() != want {
			t.Fatalf("Allocate = %v, %v; want %s", got, err, want)
		}
		used[got] = true
	}

	// Freed addresses are reused first.
	delete(used, netip.MustParseAddr("100.64.0.2"))
	if got, _ := Allocate(p, isUsed); got.String() != "100.64.0.2" {
		t.Fatalf("Allocate = %v, want reuse of 100.64.0.2", got)
	}
}

func TestAllocateExhausted(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/30") // usable: .1 and .2
	used := map[netip.Addr]bool{}
	for range 2 {
		a, err := Allocate(p, func(a netip.Addr) bool { return used[a] })
		if err != nil {
			t.Fatal(err)
		}
		used[a] = true
	}
	if _, err := Allocate(p, func(a netip.Addr) bool { return used[a] }); !errors.Is(err, ErrExhausted) {
		t.Fatalf("err = %v, want ErrExhausted", err)
	}
}

func TestAllocateRejectsBadPrefixes(t *testing.T) {
	for _, s := range []string{"fd00::/64", "10.0.0.0/31"} {
		if _, err := Allocate(netip.MustParsePrefix(s), func(netip.Addr) bool { return false }); err == nil {
			t.Errorf("%s: expected error", s)
		}
	}
}

func TestLastAddr(t *testing.T) {
	tests := map[string]string{
		"100.64.0.0/10": "100.127.255.255",
		"10.0.0.0/24":   "10.0.0.255",
		"10.0.0.0/30":   "10.0.0.3",
		"10.1.2.0/23":   "10.1.3.255",
	}
	for in, want := range tests {
		if got := lastAddr(netip.MustParsePrefix(in)); got.String() != want {
			t.Errorf("lastAddr(%s) = %s, want %s", in, got, want)
		}
	}
}
