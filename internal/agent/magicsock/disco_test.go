package magicsock

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/sneakybugmaster/transporter/internal/stun"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

func keyPair(t *testing.T) (wgkey.Key, wgkey.Key) {
	t.Helper()
	priv, err := wgkey.NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	return priv, priv.Public()
}

func TestDiscoRoundTrip(t *testing.T) {
	aPriv, aPub := keyPair(t)
	bPriv, bPub := keyPair(t)
	kAB, err := discoSharedKey(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	kBA, _ := discoSharedKey(bPriv, aPub)
	if kAB != kBA {
		t.Fatal("shared keys differ")
	}

	msgs := []discoMsg{
		{typ: msgPing, tx: newTxID()},
		{typ: msgPong, tx: newTxID(), observed: netip.MustParseAddrPort("203.0.113.9:41641")},
		{typ: msgCallMeMaybe, endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.1:41641"),
			netip.MustParseAddrPort("[2001:db8::1]:41641"),
		}},
	}
	for _, m := range msgs {
		pkt := sealDisco(kAB, aPub, m)
		if !isDisco(pkt) || stun.Is(pkt) {
			t.Fatalf("packet classification wrong for type %d", m.typ)
		}
		if discoSender(pkt) != aPub {
			t.Fatal("wrong sender")
		}
		got, err := openDisco(kBA, pkt)
		if err != nil {
			t.Fatal(err)
		}
		if got.typ != m.typ || got.tx != m.tx || got.observed != m.observed || !slices.Equal(got.endpoints, m.endpoints) {
			t.Fatalf("got %+v, want %+v", got, m)
		}
	}
}

func TestDiscoRejectsForgeries(t *testing.T) {
	aPriv, aPub := keyPair(t)
	_, bPub := keyPair(t)
	cPriv, _ := keyPair(t)
	kAB, _ := discoSharedKey(aPriv, bPub)
	kCB, _ := discoSharedKey(cPriv, bPub)

	pkt := sealDisco(kAB, aPub, discoMsg{typ: msgPing, tx: newTxID()})
	if _, err := openDisco(kCB, pkt); err == nil {
		t.Fatal("opened with the wrong key")
	}
	pkt[len(pkt)-1] ^= 1
	if _, err := openDisco(kAB, pkt); err == nil {
		t.Fatal("opened a tampered packet")
	}
}

func TestIsDiscoRejectsWireGuard(t *testing.T) {
	wg := make([]byte, 148)
	wg[0] = 1 // handshake initiation
	if isDisco(wg) {
		t.Fatal("WireGuard packet classified as disco")
	}
}

func FuzzUnmarshalDisco(f *testing.F) {
	f.Add([]byte{msgPing, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	f.Add(discoMsg{typ: msgCallMeMaybe, endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1")}}.marshal())
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = unmarshalDisco(b)
	})
}
