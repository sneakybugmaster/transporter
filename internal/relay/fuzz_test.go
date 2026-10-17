package relay

import (
	"bytes"
	"testing"

	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

func FuzzDecode(f *testing.F) {
	f.Add(encode(frameSend, wgkey.Key{1}, []byte("hello")), byte(frameSend))
	f.Add([]byte{}, byte(frameRecv))
	f.Fuzz(func(t *testing.T, b []byte, want byte) {
		key, payload, err := decode(b, want)
		if err != nil {
			return
		}
		if got := encode(want, key, payload); !bytes.Equal(got, b) {
			t.Fatalf("re-encoding %x gave %x", b, got)
		}
	})
}
