package wgkey

import (
	"encoding/json"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestKeyRoundTrip(t *testing.T) {
	priv, err := NewPrivate()
	if err != nil {
		t.Fatal(err)
	}
	if priv[0]&7 != 0 || priv[31]&128 != 0 || priv[31]&64 == 0 {
		t.Fatal("private key not clamped")
	}
	want, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	if string(pub[:]) != string(want) {
		t.Fatal("public key mismatch")
	}

	for _, parse := range []func() (Key, error){
		func() (Key, error) { return Parse(pub.String()) },
		func() (Key, error) { return ParseHex(pub.Hex()) },
	} {
		got, err := parse()
		if err != nil || got != pub {
			t.Fatalf("parse = %v, %v", got, err)
		}
	}

	b, err := json.Marshal(struct{ K Key }{pub})
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ K Key }
	if err := json.Unmarshal(b, &out); err != nil || out.K != pub {
		t.Fatalf("json round trip = %v, %v", out.K, err)
	}

	if _, err := Parse("AAAA"); err == nil {
		t.Fatal("short key accepted")
	}
}
