package datalock

import (
	"errors"
	"testing"
)

func TestExclusive(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Acquire: %v", err)
	}
	if err := l.Release(); err != nil {
		t.Fatal(err)
	}
	l, err = Acquire(dir)
	if err != nil {
		t.Fatalf("Acquire after Release: %v", err)
	}
	_ = l.Release()
}
