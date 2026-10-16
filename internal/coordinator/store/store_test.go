package store

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

var testPrefix = netip.MustParsePrefix("100.64.0.0/10")

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := OpenMemory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func wgKey(b byte) [32]byte {
	var k [32]byte
	k[0] = b
	return k
}

func register(t *testing.T, s *Store, authKey string, key byte, hostname string) (Node, string) {
	t.Helper()
	n, tok, err := s.RegisterNode(context.Background(), RegisterRequest{
		AuthKey: authKey, WGPublicKey: wgKey(key), Hostname: hostname, OS: "linux", Prefix: testPrefix,
	})
	if err != nil {
		t.Fatalf("register %s: %v", hostname, err)
	}
	return n, tok
}

func TestOpenOnDiskIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true})
	if err != nil {
		t.Fatal(err)
	}
	register(t, s, secret, 1, "alpha")
	_ = s.Close()

	s, err = Open(ctx, dir) // re-running migrations must be a no-op
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	nodes, err := s.ListNodes(ctx)
	if err != nil || len(nodes) != 1 || nodes[0].Name != "alpha" {
		t.Fatalf("nodes = %+v, err = %v", nodes, err)
	}
}

func TestRegisterAllocatesAddressesAndNames(t *testing.T) {
	s := newStore(t)
	_, secret, err := s.CreateAuthKey(context.Background(), AuthKeyOptions{Reusable: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, AuthKeyPrefix) {
		t.Fatalf("secret %q lacks prefix", secret)
	}

	a, tokA := register(t, s, secret, 1, "Web-Server.example.com")
	b, _ := register(t, s, secret, 2, "web-server")
	if a.IPv4.String() != "100.64.0.1" || b.IPv4.String() != "100.64.0.2" {
		t.Fatalf("addresses = %s, %s", a.IPv4, b.IPv4)
	}
	if a.Name != "web-server" || b.Name != "web-server-2" {
		t.Fatalf("names = %q, %q", a.Name, b.Name)
	}

	got, err := s.NodeByToken(context.Background(), tokA)
	if err != nil || got.ID != a.ID {
		t.Fatalf("NodeByToken = %+v, %v", got, err)
	}
	if _, err := s.NodeByToken(context.Background(), "trn_bogus"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bogus token err = %v", err)
	}
}

func TestReRegisterSameKeyKeepsNodeAndRotatesToken(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, secret, _ := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true})

	first, oldTok := register(t, s, secret, 1, "alpha")
	second, newTok := register(t, s, secret, 1, "alpha-renamed")
	if first.ID != second.ID || first.IPv4 != second.IPv4 || second.Hostname != "alpha-renamed" {
		t.Fatalf("first = %+v, second = %+v", first, second)
	}
	if _, err := s.NodeByToken(ctx, oldTok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old token still valid: %v", err)
	}
	if _, err := s.NodeByToken(ctx, newTok); err != nil {
		t.Fatal(err)
	}
}

func TestAuthKeyValidity(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	_, single, _ := s.CreateAuthKey(ctx, AuthKeyOptions{})
	register(t, s, single, 1, "a")
	if _, _, err := s.RegisterNode(ctx, RegisterRequest{AuthKey: single, WGPublicKey: wgKey(2), Prefix: testPrefix}); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("single-use key reused: err = %v", err)
	}

	_, expiring, _ := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true, TTL: time.Hour})
	register(t, s, expiring, 3, "b")
	now = now.Add(time.Hour)
	if _, _, err := s.RegisterNode(ctx, RegisterRequest{AuthKey: expiring, WGPublicKey: wgKey(4), Prefix: testPrefix}); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("expired key accepted: err = %v", err)
	}

	k, revoked, _ := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true})
	if err := s.RevokeAuthKey(ctx, k.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RegisterNode(ctx, RegisterRequest{AuthKey: revoked, WGPublicKey: wgKey(5), Prefix: testPrefix}); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("revoked key accepted: err = %v", err)
	}

	if _, _, err := s.RegisterNode(ctx, RegisterRequest{AuthKey: "trk_unknown", WGPublicKey: wgKey(6), Prefix: testPrefix}); !errors.Is(err, ErrInvalidAuthKey) {
		t.Fatalf("unknown key accepted: err = %v", err)
	}

	keys, err := s.ListAuthKeys(ctx)
	if err != nil || len(keys) != 3 {
		t.Fatalf("keys = %+v, err = %v", keys, err)
	}
}

func TestEnsureAuthKey(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	const secret = "bootstrap-secret-1234"
	a, err := s.EnsureAuthKey(ctx, secret, AuthKeyOptions{Reusable: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.EnsureAuthKey(ctx, secret, AuthKeyOptions{Reusable: true})
	if err != nil || a.ID != b.ID {
		t.Fatalf("second ensure = %+v, %v (want id %s)", b, err, a.ID)
	}
	register(t, s, secret, 1, "a")
	if _, err := s.EnsureAuthKey(ctx, "short", AuthKeyOptions{}); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestEndpointsAndDelete(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	_, secret, _ := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true})
	a, _ := register(t, s, secret, 1, "a")

	if err := s.UpdateNodeEndpoints(ctx, a.ID, []string{"192.0.2.1:41641", "10.0.0.5:41641"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.NodeByID(ctx, a.ID)
	if err != nil || len(got.Endpoints) != 2 || got.Endpoints[0] != "192.0.2.1:41641" {
		t.Fatalf("node = %+v, err = %v", got, err)
	}

	if err := s.DeleteNode(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteNode(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete err = %v", err)
	}
	// The freed address is reused.
	b, _ := register(t, s, secret, 2, "b")
	if b.IPv4 != a.IPv4 {
		t.Fatalf("address %s not reused, got %s", a.IPv4, b.IPv4)
	}
}

func TestSanitizeName(t *testing.T) {
	tests := map[string]string{
		"Laptop":                "laptop",
		"web_01.prod.example":   "web-01",
		"--weird  name!!":       "weird-name",
		"":                      "node",
		"!!!":                   "node",
		strings.Repeat("a", 80): strings.Repeat("a", 63),
	}
	for in, want := range tests {
		if got := SanitizeName(in); got != want {
			t.Errorf("SanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}
