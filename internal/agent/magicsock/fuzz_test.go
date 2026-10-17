package magicsock

import (
	"net/netip"
	"testing"
)

func FuzzDisco(f *testing.F) {
	var key [32]byte
	key[0] = 9
	f.Add(sealDisco(key, [32]byte{1}, 1, discoMsg{typ: msgPing, tx: newTxID()}))
	f.Add(sealDisco(key, [32]byte{1}, 2, discoMsg{typ: msgCallMeMaybe, endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if !isDisco(b) {
			return
		}
		_ = discoSender(b)
		_, _, _ = openDisco(key, b)
	})
}

func FuzzReplayWindow(f *testing.F) {
	f.Add(uint64(5), uint64(3), uint64(5))
	f.Fuzz(func(t *testing.T, a, b, c uint64) {
		var w replayWindow
		seen := map[uint64]bool{}
		for _, n := range []uint64{a, b, c, a} {
			if w.accept(n) && seen[n] {
				t.Fatalf("counter %d accepted twice", n)
			}
			seen[n] = true
		}
	})
}
