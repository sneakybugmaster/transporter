// Package stun implements the small subset of STUN (RFC 5389) Transporter
// needs: binding requests and responses carrying XOR-MAPPED-ADDRESS, so a
// node can learn the public address its NAT maps its UDP socket to.
package stun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	headerLen   = 20
	magicCookie = 0x2112A442

	typeBindingRequest  = 0x0001
	typeBindingResponse = 0x0101

	attrXORMappedAddress = 0x0020
	attrMappedAddress    = 0x0001

	familyIPv4 = 0x01
	familyIPv6 = 0x02
)

// TxID is a STUN transaction ID.
type TxID [12]byte

// NewTxID returns a random transaction ID.
func NewTxID() TxID {
	var t TxID
	_, _ = rand.Read(t[:])
	return t
}

// Is reports whether b looks like a STUN message. It is cheap enough to run
// on every packet arriving on a socket shared with other protocols.
func Is(b []byte) bool {
	return len(b) >= headerLen &&
		b[0]&0xC0 == 0 &&
		binary.BigEndian.Uint32(b[4:8]) == magicCookie &&
		int(binary.BigEndian.Uint16(b[2:4]))+headerLen == len(b)
}

// Request builds a binding request.
func Request(tx TxID) []byte {
	b := make([]byte, headerLen)
	binary.BigEndian.PutUint16(b[0:2], typeBindingRequest)
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])
	return b
}

// ParseRequest returns the transaction ID of a binding request.
func ParseRequest(b []byte) (TxID, error) {
	var tx TxID
	if !Is(b) || binary.BigEndian.Uint16(b[0:2]) != typeBindingRequest {
		return tx, errors.New("stun: not a binding request")
	}
	copy(tx[:], b[8:20])
	return tx, nil
}

// Response builds a binding success response reporting addr.
func Response(tx TxID, addr netip.AddrPort) []byte {
	ip := addr.Addr().Unmap()
	family, ipLen := byte(familyIPv4), 4
	if ip.Is6() {
		family, ipLen = familyIPv6, 16
	}
	attrLen := 4 + ipLen
	b := make([]byte, headerLen+4+attrLen)
	binary.BigEndian.PutUint16(b[0:2], typeBindingResponse)
	binary.BigEndian.PutUint16(b[2:4], uint16(4+attrLen)) //nolint:gosec // small constant
	binary.BigEndian.PutUint32(b[4:8], magicCookie)
	copy(b[8:20], tx[:])

	a := b[headerLen:]
	binary.BigEndian.PutUint16(a[0:2], attrXORMappedAddress)
	binary.BigEndian.PutUint16(a[2:4], uint16(attrLen)) //nolint:gosec // small constant
	a[5] = family
	binary.BigEndian.PutUint16(a[6:8], addr.Port()^uint16(magicCookie>>16))
	xorIP(a[8:8+ipLen], ip.AsSlice(), tx)
	return b
}

// ParseResponse returns the transaction ID and mapped address of a binding
// success response.
func ParseResponse(b []byte) (TxID, netip.AddrPort, error) {
	var tx TxID
	if !Is(b) || binary.BigEndian.Uint16(b[0:2]) != typeBindingResponse {
		return tx, netip.AddrPort{}, errors.New("stun: not a binding response")
	}
	copy(tx[:], b[8:20])
	var fallback netip.AddrPort
	for attrs := b[headerLen:]; len(attrs) >= 4; {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		n := int(binary.BigEndian.Uint16(attrs[2:4]))
		if 4+n > len(attrs) {
			break
		}
		val := attrs[4 : 4+n]
		switch typ {
		case attrXORMappedAddress:
			if ap, ok := parseAddr(val, tx, true); ok {
				return tx, ap, nil
			}
		case attrMappedAddress:
			if ap, ok := parseAddr(val, tx, false); ok {
				fallback = ap
			}
		}
		padded := 4 + (n+3)&^3 // attributes are padded to 4 bytes
		if padded > len(attrs) {
			break
		}
		attrs = attrs[padded:]
	}
	if fallback.IsValid() {
		return tx, fallback, nil
	}
	return tx, netip.AddrPort{}, errors.New("stun: response has no mapped address")
}

func parseAddr(v []byte, tx TxID, xor bool) (netip.AddrPort, bool) {
	if len(v) < 4 {
		return netip.AddrPort{}, false
	}
	ipLen := map[byte]int{familyIPv4: 4, familyIPv6: 16}[v[1]]
	if ipLen == 0 || len(v) < 4+ipLen {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	ipb := make([]byte, ipLen)
	if xor {
		port ^= uint16(magicCookie >> 16)
		xorIP(ipb, v[4:4+ipLen], tx)
	} else {
		copy(ipb, v[4:4+ipLen])
	}
	ip, ok := netip.AddrFromSlice(ipb)
	return netip.AddrPortFrom(ip, port), ok
}

// xorIP XORs src with the magic cookie followed by the transaction ID.
func xorIP(dst, src []byte, tx TxID) {
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], magicCookie)
	copy(key[4:], tx[:])
	for i := range src {
		dst[i] = src[i] ^ key[i]
	}
}
