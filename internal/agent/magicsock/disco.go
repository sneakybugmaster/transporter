package magicsock

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/netip"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"

	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

// Disco ("discovery") messages share the WireGuard UDP socket. They let peers
// probe candidate paths (ping/pong) and ask each other to start probing
// (call-me-maybe, sent through the relay) so that both NATs open a mapping at
// the same time. They are sealed with a key derived from the two nodes'
// WireGuard keys, so only mesh members can send them.
//
// Wire format:
//
//	magic (6) | sender public key (32) | nonce (24) | XChaCha20-Poly1305(payload)
//
// The magic cannot be mistaken for WireGuard (whose messages start with a
// type byte 1..4 followed by three zero bytes) or STUN (top two bits zero).
var discoMagic = [6]byte{'T', 'P', 'D', 'S', 'C', 0x01}

const (
	discoHeaderLen = len(discoMagic) + 32 + chacha20poly1305.NonceSizeX

	msgPing        = 1
	msgPong        = 2
	msgCallMeMaybe = 3

	txIDLen    = 12
	addrLen    = 18 // 16-byte IP (v4-mapped for IPv4) + 2-byte port
	maxCMMAddr = 32
)

type txID [txIDLen]byte

func newTxID() txID {
	var t txID
	_, _ = rand.Read(t[:])
	return t
}

// discoMsg is a decoded disco payload.
type discoMsg struct {
	typ       byte
	tx        txID             // ping, pong
	observed  netip.AddrPort   // pong: the address the ping arrived from
	endpoints []netip.AddrPort // call-me-maybe
}

func isDisco(b []byte) bool {
	return len(b) > discoHeaderLen && [6]byte(b[:6]) == discoMagic
}

// discoSharedKey derives the symmetric disco key between two nodes. Both
// sides compute the same value: X25519(a_priv, b_pub) == X25519(b_priv, a_pub).
func discoSharedKey(priv, peerPub wgkey.Key) ([32]byte, error) {
	dh, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write([]byte("transporter disco v1"))
	h.Write(dh)
	var k [32]byte
	copy(k[:], h.Sum(nil))
	return k, nil
}

// sealDisco encrypts m for the peer sharing key.
func sealDisco(key [32]byte, sender wgkey.Key, m discoMsg) []byte {
	aead, _ := chacha20poly1305.NewX(key[:]) // key size is fixed: cannot fail
	out := make([]byte, discoHeaderLen, discoHeaderLen+64)
	copy(out, discoMagic[:])
	copy(out[6:], sender[:])
	nonce := out[6+32 : discoHeaderLen]
	_, _ = rand.Read(nonce)
	return aead.Seal(out, nonce, m.marshal(), nil)
}

// discoSender returns the claimed sender of a disco packet; the claim is only
// trusted once openDisco succeeds with that sender's shared key.
func discoSender(b []byte) wgkey.Key {
	var k wgkey.Key
	copy(k[:], b[6:6+32])
	return k
}

func openDisco(key [32]byte, b []byte) (discoMsg, error) {
	aead, _ := chacha20poly1305.NewX(key[:])
	nonce := b[6+32 : discoHeaderLen]
	pt, err := aead.Open(nil, nonce, b[discoHeaderLen:], nil)
	if err != nil {
		return discoMsg{}, errors.New("disco: authentication failed")
	}
	return unmarshalDisco(pt)
}

func (m discoMsg) marshal() []byte {
	b := []byte{m.typ}
	switch m.typ {
	case msgPing:
		b = append(b, m.tx[:]...)
	case msgPong:
		b = append(b, m.tx[:]...)
		b = appendAddr(b, m.observed)
	case msgCallMeMaybe:
		for _, ep := range m.endpoints[:min(len(m.endpoints), maxCMMAddr)] {
			b = appendAddr(b, ep)
		}
	}
	return b
}

func unmarshalDisco(b []byte) (discoMsg, error) {
	if len(b) == 0 {
		return discoMsg{}, errors.New("disco: empty message")
	}
	m := discoMsg{typ: b[0]}
	body := b[1:]
	switch m.typ {
	case msgPing:
		if len(body) < txIDLen {
			return discoMsg{}, errors.New("disco: short ping")
		}
		copy(m.tx[:], body)
	case msgPong:
		if len(body) < txIDLen+addrLen {
			return discoMsg{}, errors.New("disco: short pong")
		}
		copy(m.tx[:], body)
		m.observed = parseAddr(body[txIDLen:])
	case msgCallMeMaybe:
		for len(body) >= addrLen && len(m.endpoints) < maxCMMAddr {
			if ap := parseAddr(body); ap.IsValid() && ap.Port() != 0 {
				m.endpoints = append(m.endpoints, ap)
			}
			body = body[addrLen:]
		}
	default:
		return discoMsg{}, errors.New("disco: unknown message type")
	}
	return m, nil
}

func appendAddr(b []byte, ap netip.AddrPort) []byte {
	ip := ap.Addr().As16()
	b = append(b, ip[:]...)
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

func parseAddr(b []byte) netip.AddrPort {
	ip := netip.AddrFrom16([16]byte(b[:16])).Unmap()
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[16:18]))
}
