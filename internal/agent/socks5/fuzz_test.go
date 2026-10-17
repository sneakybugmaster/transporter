package socks5

import (
	"bytes"
	"io"
	"testing"
)

// rw reads from a fixed input and discards writes.
type rw struct{ io.Reader }

func (rw) Write(p []byte) (int, error) { return len(p), nil }

func FuzzHandshake(f *testing.F) {
	f.Add([]byte{5, 1, 0, 5, 1, 0, 3, 3, 'w', 'e', 'b', 0, 80})
	f.Add([]byte{5, 1, 0, 5, 1, 0, 1, 10, 0, 0, 1, 1, 187})
	f.Add([]byte{4, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = handshake(rw{bytes.NewReader(b)})
	})
}
