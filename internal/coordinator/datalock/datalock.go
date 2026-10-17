// Package datalock marks a data directory as in use by a running
// coordinator, so offline operations such as restore can refuse to run.
package datalock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("data directory is in use by a running coordinator")

// Lock is a held lock.
type Lock struct{ f *os.File }

// Acquire takes the lock on dir without waiting.
func Acquire(dir string) (*Lock, error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // operator-supplied data dir
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w (%s)", ErrLocked, dir)
	}
	return &Lock{f: f}, nil
}

// Release drops the lock.
func (l *Lock) Release() error { return l.f.Close() }
