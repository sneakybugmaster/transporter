// Package relay forwards already-encrypted packets between nodes that cannot
// reach each other directly. Nodes hold a WebSocket to the coordinator and
// address each other by WireGuard public key; the relay never sees plaintext.
//
// Frames are binary WebSocket messages:
//
//	client -> server: 0x01 | destination key (32) | payload
//	server -> client: 0x02 | source key (32)      | payload
package relay

import (
	"errors"

	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

// Path is where the relay is mounted on the coordinator.
const Path = "/relay/v1"

const (
	frameSend = 0x01
	frameRecv = 0x02
	headerLen = 1 + 32
	// MaxPayload bounds a single packet; WireGuard packets are far smaller.
	MaxPayload = 64 << 10
)

func encode(typ byte, key wgkey.Key, payload []byte) []byte {
	b := make([]byte, headerLen+len(payload))
	b[0] = typ
	copy(b[1:headerLen], key[:])
	copy(b[headerLen:], payload)
	return b
}

func decode(b []byte, want byte) (wgkey.Key, []byte, error) {
	if len(b) < headerLen || b[0] != want {
		return wgkey.Key{}, nil, errors.New("relay: malformed frame")
	}
	var k wgkey.Key
	copy(k[:], b[1:headerLen])
	return k, b[headerLen:], nil
}
