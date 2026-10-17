// Package wgkey handles WireGuard Curve25519 keys.
package wgkey

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// Key is a 32-byte WireGuard key.
type Key [32]byte

// NewPrivate returns a new, clamped private key.
func NewPrivate() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return Key{}, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

// Public derives the public key from a private key.
func (k Key) Public() Key {
	var pub Key
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&k))
	return pub
}

// String returns the standard base64 encoding used by wg(8).
func (k Key) String() string { return base64.StdEncoding.EncodeToString(k[:]) }

// Hex returns the hex encoding used by the UAPI configuration protocol.
func (k Key) Hex() string { return hex.EncodeToString(k[:]) }

// IsZero reports whether k is all zeros.
func (k Key) IsZero() bool { return k == Key{} }

// Parse decodes a base64 key.
func Parse(s string) (Key, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("invalid key: %w", err)
	}
	return FromBytes(b)
}

// ParseHex decodes a hex key as returned by the UAPI.
func ParseHex(s string) (Key, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return Key{}, fmt.Errorf("invalid key: %w", err)
	}
	return FromBytes(b)
}

// FromBytes copies a 32-byte slice into a Key.
func FromBytes(b []byte) (Key, error) {
	var k Key
	if len(b) != len(k) {
		return Key{}, fmt.Errorf("invalid key length %d", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// MarshalText implements encoding.TextMarshaler (base64).
func (k Key) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler (base64).
func (k *Key) UnmarshalText(b []byte) error {
	parsed, err := Parse(string(b))
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// Bytes returns a copy of the key as a slice.
func (k Key) Bytes() []byte { return append([]byte(nil), k[:]...) }
