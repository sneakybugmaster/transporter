package stun

import (
	"net/netip"
	"testing"
)

func FuzzParse(f *testing.F) {
	tx := NewTxID()
	f.Add(Request(tx))
	f.Add(Response(tx, netip.MustParseAddrPort("203.0.113.7:41641")))
	f.Add(Response(tx, netip.MustParseAddrPort("[2001:db8::7]:41641")))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = Is(b)
		_, _ = ParseRequest(b)
		if id, addr, err := ParseResponse(b); err == nil {
			// Whatever parses must survive a round trip.
			id2, addr2, err := ParseResponse(Response(id, addr))
			if err != nil || id2 != id || addr2 != addr {
				t.Fatalf("round trip: %v %v %v", id2, addr2, err)
			}
		}
	})
}
