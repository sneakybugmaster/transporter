package magicdns

import (
	"context"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func FuzzHandle(f *testing.F) {
	r := &Resolver{}
	r.SetConfig(Config{Domain: "mesh.internal", Nodes: map[string]netip.Addr{"web": netip.MustParseAddr("100.64.0.2")}})
	for _, q := range []struct {
		name string
		typ  dnsmessage.Type
	}{{"web.mesh.internal.", dnsmessage.TypeA}, {"2.0.64.100.in-addr.arpa.", dnsmessage.TypePTR}, {"x.example.", dnsmessage.TypeAAAA}} {
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 1})
		_ = b.StartQuestions()
		_ = b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(q.name), Type: q.typ, Class: dnsmessage.ClassINET})
		msg, _ := b.Finish()
		f.Add(msg)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		resp := r.Handle(context.Background(), b)
		if resp == nil {
			return
		}
		var m dnsmessage.Message
		if err := m.Unpack(resp); err != nil {
			t.Fatalf("answer does not parse: %v", err)
		}
		if !m.Response {
			t.Fatal("answer is not a response")
		}
	})
}
