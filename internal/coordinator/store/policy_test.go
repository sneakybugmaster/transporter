package store

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
)

func TestTagsAndRoutes(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, tagged, _ := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true, Tags: []string{"tag:router"}})
	keys, _ := s.ListAuthKeys(ctx)
	if !slices.Equal(keys[0].Tags, []string{"tag:router"}) {
		t.Fatalf("key tags = %v", keys[0].Tags)
	}
	n, _ := register(t, s, tagged, 1, "gw")
	if !slices.Equal(n.Tags, []string{"tag:router"}) {
		t.Fatalf("node enrolled with tags %v", n.Tags)
	}

	n, err := s.SetNodeTags(ctx, n.ID, []string{"tag:a", "tag:b"})
	if err != nil || !slices.Equal(n.Tags, []string{"tag:a", "tag:b"}) {
		t.Fatalf("SetNodeTags = %v, %v", n.Tags, err)
	}
	// Re-enrolling with an untagged key keeps the tags; a tagged key resets them.
	_, plain, _ := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true})
	if n, _ = register(t, s, plain, 1, "gw"); !slices.Equal(n.Tags, []string{"tag:a", "tag:b"}) {
		t.Fatalf("untagged re-enroll changed tags to %v", n.Tags)
	}
	if n, _ = register(t, s, tagged, 1, "gw"); !slices.Equal(n.Tags, []string{"tag:router"}) {
		t.Fatalf("tagged re-enroll left tags %v", n.Tags)
	}

	lan, exit := netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("0.0.0.0/0")
	if err := s.SetAdvertisedRoutes(ctx, n.ID, []netip.Prefix{lan, exit}); err != nil {
		t.Fatal(err)
	}
	n, err = s.SetApprovedRoutes(ctx, n.ID, []netip.Prefix{lan, netip.MustParsePrefix("10.9.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	if got := n.Routes(); !slices.Equal(got, []netip.Prefix{lan}) {
		t.Fatalf("effective routes = %v, want only what is advertised and approved", got)
	}
	if _, err := s.SetApprovedRoutes(ctx, "missing", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("approve on a missing node: %v", err)
	}
}

func TestAudit(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	for _, a := range []string{"one", "two", "three"} {
		if err := s.AppendAudit(ctx, AuditEntry{Actor: "admin", Action: a, Target: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ListAudit(ctx, 2, 0)
	if err != nil || len(got) != 2 || got[0].Action != "three" || got[1].Action != "two" {
		t.Fatalf("ListAudit = %+v, %v", got, err)
	}
	older, _ := s.ListAudit(ctx, 10, got[1].ID)
	if len(older) != 1 || older[0].Action != "one" || older[0].Time.IsZero() {
		t.Fatalf("older page = %+v", older)
	}
}

func TestMagicDNSAddressNeverAllocated(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, secret, _ := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true})
	// A /29 around the address: six usable addresses, one of them reserved,
	// so the sixth registration fails.
	prefix := netip.MustParsePrefix("100.100.100.96/29")
	for i := range 6 {
		n, _, err := s.RegisterNode(ctx, RegisterRequest{AuthKey: secret, WGPublicKey: wgKey(byte(i + 1)), Hostname: "n", Prefix: prefix})
		if err != nil {
			if i == 5 {
				break // exhausted: 6 usable addresses minus the reserved one
			}
			t.Fatal(err)
		}
		if n.IPv4 == netip.MustParseAddr("100.100.100.100") {
			t.Fatal("allocated the MagicDNS address")
		}
	}
}

func TestBackup(t *testing.T) {
	ctx := context.Background()
	s, err := Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, secret, _ := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true})
	register(t, s, secret, 1, "alpha")

	path := t.TempDir() + "/backup.db"
	if err := s.Backup(ctx, path); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup(ctx, path); err == nil {
		t.Fatal("backup overwrote an existing file")
	}
	b, err := OpenFile(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := b.ListNodes(ctx); err != nil || len(n) != 1 || n[0].Name != "alpha" {
		t.Fatalf("nodes in backup = %v, %v", n, err)
	}
}
