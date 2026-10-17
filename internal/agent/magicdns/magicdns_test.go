package magicdns

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0xbeef, RecursionDesired: true})
	_ = b.StartQuestions()
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func parse(t *testing.T, resp []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(resp); err != nil {
		t.Fatalf("unpack response: %v", err)
	}
	if m.ID != 0xbeef || !m.Response {
		t.Fatalf("bad header %+v", m.Header)
	}
	return m
}

func newResolver() *Resolver {
	r := &Resolver{}
	r.SetConfig(Config{
		Domain: "Mesh.Internal.",
		Nodes:  map[string]netip.Addr{"web": netip.MustParseAddr("100.64.0.2"), "db": netip.MustParseAddr("100.64.0.3")},
	})
	return r
}

func TestMeshNames(t *testing.T) {
	r := newResolver()
	ctx := context.Background()

	m := parse(t, r.Handle(ctx, query(t, "WEB.mesh.internal.", dnsmessage.TypeA)))
	if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 1 {
		t.Fatalf("A web: %+v", m)
	}
	if a := m.Answers[0].Body.(*dnsmessage.AResource).A; netip.AddrFrom4(a) != netip.MustParseAddr("100.64.0.2") {
		t.Fatalf("A web = %v", a)
	}
	if m = parse(t, r.Handle(ctx, query(t, "web.mesh.internal.", dnsmessage.TypeAAAA))); m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
		t.Fatalf("AAAA web should be NODATA: %+v", m)
	}
	if m = parse(t, r.Handle(ctx, query(t, "nope.mesh.internal.", dnsmessage.TypeA))); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("unknown node: %v", m.RCode)
	}
	if m = parse(t, r.Handle(ctx, query(t, "example.com.", dnsmessage.TypeA))); m.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("outside the mesh: %v", m.RCode)
	}
	m = parse(t, r.Handle(ctx, query(t, "3.0.64.100.in-addr.arpa.", dnsmessage.TypePTR)))
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.PTRResource).PTR.String() != "db.mesh.internal." {
		t.Fatalf("PTR: %+v", m)
	}

	if ip, ok := r.Lookup("db"); !ok || ip != netip.MustParseAddr("100.64.0.3") {
		t.Fatalf("Lookup(db) = %v %v", ip, ok)
	}
	if _, ok := r.Lookup("db.mesh.internal."); !ok {
		t.Fatal("Lookup of the FQDN failed")
	}
	if r.Handle(ctx, []byte{1, 2, 3}) != nil {
		t.Fatal("answered garbage")
	}
}

func TestSplitDNS(t *testing.T) {
	// A fake upstream that answers everything with 10.9.9.9.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil {
				continue
			}
			m.Response = true
			m.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.AResource{A: [4]byte{10, 9, 9, 9}},
			}}
			out, _ := m.Pack()
			_, _ = pc.WriteTo(out, from)
		}
	}()
	up := netip.MustParseAddrPort(pc.LocalAddr().String())
	dead := netip.MustParseAddrPort("127.0.0.1:1") // nothing listens: refused

	r := newResolver()
	r.SetConfig(Config{
		Domain: "mesh.internal",
		Split:  []Split{{Domain: "corp.example", Resolvers: []netip.AddrPort{dead, up}}},
	})
	if got := r.Domains(); len(got) != 2 || got[1] != "corp.example" {
		t.Fatalf("Domains = %v", got)
	}
	m := parse(t, r.Handle(context.Background(), query(t, "git.corp.example.", dnsmessage.TypeA)))
	if len(m.Answers) != 1 || m.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 9, 9, 9} {
		t.Fatalf("forwarded answer: %+v", m)
	}
}
