package state

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadSave(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested")

	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.PrivateKey.IsZero() || s.Registered("http://c") {
		t.Fatalf("fresh state = %+v", s)
	}
	s.CoordinatorURL, s.NodeID, s.NodeToken, s.Name = "http://c", "id1", "trn_x", "alpha"
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(filepath.Join(dir, fileName))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, err = %v", fi.Mode(), err)
		}
	}

	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *s {
		t.Fatalf("loaded %+v, want %+v", got, s)
	}
	if !got.Registered("http://c") || got.Registered("http://other") {
		t.Fatal("Registered mismatch")
	}
}

func TestLoadRejectsCorruptState(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("corrupt state accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("state without key accepted")
	}
}
