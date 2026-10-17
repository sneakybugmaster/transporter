package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const goodPassword = "correct horse battery"

func TestPasswordHashing(t *testing.T) {
	h := hashPassword(goodPassword)
	if h == hashPassword(goodPassword) {
		t.Fatal("hashes are not salted")
	}
	if ok, err := verifyPassword(goodPassword, h); err != nil || !ok {
		t.Fatalf("verify = %v, %v", ok, err)
	}
	if ok, _ := verifyPassword("wrong password!", h); ok {
		t.Fatal("wrong password verified")
	}
	if _, err := verifyPassword(goodPassword, "$bcrypt$x"); err == nil {
		t.Fatal("foreign hash accepted")
	}
}

func TestFirstAdminIsCreatedOnce(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	if _, err := s.CreateFirstAdmin(ctx, "admin", "short"); err == nil {
		t.Fatal("short password accepted")
	}

	// Concurrent setups: exactly one wins.
	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := range errs {
		wg.Go(func() { _, errs[i] = s.CreateFirstAdmin(ctx, "admin", goodPassword) })
	}
	wg.Wait()
	wins := 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case !errors.Is(err, ErrSetupDone):
			t.Fatalf("unexpected error %v", err)
		}
	}
	if n, _ := s.AdminCount(ctx); wins != 1 || n != 1 {
		t.Fatalf("wins = %d, admins = %d", wins, n)
	}
	if _, err := s.CreateAdmin(ctx, "ADMIN", goodPassword); !errors.Is(err, ErrConflict) {
		t.Fatalf("case-insensitive duplicate: err = %v", err)
	}
}

func TestAuthenticateAndSessions(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	a, err := s.CreateFirstAdmin(ctx, "admin", goodPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "admin", "wrong password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: err = %v", err)
	}
	if _, err := s.Authenticate(ctx, "nobody", goodPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: err = %v", err)
	}
	got, err := s.Authenticate(ctx, " admin ", goodPassword)
	if err != nil || got.ID != a.ID {
		t.Fatalf("Authenticate = %+v, %v", got, err)
	}

	tok, _, err := s.CreateSession(ctx, a.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.SessionAdmin(ctx, tok); err != nil || got.Username != "admin" {
		t.Fatalf("SessionAdmin = %+v, %v", got, err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := s.SessionAdmin(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session: err = %v", err)
	}

	tok, _, _ = s.CreateSession(ctx, a.ID, time.Hour)
	if err := s.DeleteSession(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionAdmin(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session: err = %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	a, _ := s.CreateFirstAdmin(ctx, "admin", goodPassword)
	keep, _, _ := s.CreateSession(ctx, a.ID, time.Hour)
	other, _, _ := s.CreateSession(ctx, a.ID, time.Hour)

	if err := s.ChangePassword(ctx, a.ID, "wrong password", "a new password!", keep); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current password: err = %v", err)
	}
	if err := s.ChangePassword(ctx, a.ID, goodPassword, "short", keep); err == nil {
		t.Fatal("short new password accepted")
	}
	if err := s.ChangePassword(ctx, a.ID, goodPassword, "a new password!", keep); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, "admin", "a new password!"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionAdmin(ctx, keep); err != nil {
		t.Fatalf("current session ended: %v", err)
	}
	if _, err := s.SessionAdmin(ctx, other); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other session survived: %v", err)
	}
}

func TestSettingsAndRename(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if v, err := s.Setting(ctx, SettingPublicURL); err != nil || v != "" {
		t.Fatalf("unset setting = %q, %v", v, err)
	}
	for _, v := range []string{"https://a.example", "https://b.example"} {
		if err := s.SetSetting(ctx, SettingPublicURL, v); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.Setting(ctx, SettingPublicURL); got != v {
			t.Fatalf("setting = %q, want %q", got, v)
		}
	}

	_, secret, _ := s.CreateAuthKey(ctx, AuthKeyOptions{Reusable: true})
	a, _ := register(t, s, secret, 1, "alpha")
	register(t, s, secret, 2, "bravo")
	got, err := s.RenameNode(ctx, a.ID, "Web Server 1")
	if err != nil || got.Name != "web-server-1" {
		t.Fatalf("rename = %+v, %v", got, err)
	}
	if _, err := s.RenameNode(ctx, a.ID, "bravo"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: err = %v", err)
	}
	if _, err := s.RenameNode(ctx, "missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing node: err = %v", err)
	}
}
