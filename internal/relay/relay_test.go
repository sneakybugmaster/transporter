package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type env struct {
	srv  *Server
	url  string
	mu   sync.Mutex
	keys map[string]wgkey.Key // token -> key
}

func newEnv(t *testing.T, bytesPerSec int) *env {
	t.Helper()
	e := &env{keys: map[string]wgkey.Key{}}
	e.srv = NewServer(func(_ context.Context, tok string) (wgkey.Key, error) {
		e.mu.Lock()
		k, ok := e.keys[tok]
		e.mu.Unlock()
		if !ok {
			return wgkey.Key{}, errors.New("unknown")
		}
		return k, nil
	}, bytesPerSec, 0, discard)
	hs := httptest.NewServer(e.srv)
	t.Cleanup(hs.Close)
	e.url = hs.URL
	return e
}

func (e *env) client(t *testing.T, ctx context.Context, b byte) (*Client, wgkey.Key) {
	t.Helper()
	k := wgkey.Key{b}
	tok := fmt.Sprintf("token-%d", b)
	e.mu.Lock()
	e.keys[tok] = k
	e.mu.Unlock()
	c, err := NewClient(e.url, tok, discard)
	if err != nil {
		t.Fatal(err)
	}
	go c.Run(ctx)
	deadline := time.Now().Add(5 * time.Second)
	for !e.srv.Connected(k) || !c.Connected() {
		if time.Now().After(deadline) {
			t.Fatal("client did not connect")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return c, k
}

func recv(t *testing.T, c *Client) Packet {
	t.Helper()
	select {
	case p := <-c.Recv():
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("no packet received")
		return Packet{}
	}
}

func TestForwarding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := newEnv(t, 0)
	a, ka := e.client(t, ctx, 1)
	b, kb := e.client(t, ctx, 2)

	if err := a.Send(ctx, kb, []byte("hello b")); err != nil {
		t.Fatal(err)
	}
	p := recv(t, b)
	if p.From != ka || !bytes.Equal(p.Payload, []byte("hello b")) {
		t.Fatalf("b got %+v", p)
	}
	if err := b.Send(ctx, ka, []byte("hi a")); err != nil {
		t.Fatal(err)
	}
	if p := recv(t, a); p.From != kb || string(p.Payload) != "hi a" {
		t.Fatalf("a got %+v", p)
	}

	// Packets to unknown nodes are dropped without breaking the connection.
	if err := a.Send(ctx, wgkey.Key{9}, []byte("nobody")); err != nil {
		t.Fatal(err)
	}
	if err := a.Send(ctx, kb, []byte("still works")); err != nil {
		t.Fatal(err)
	}
	if p := recv(t, b); string(p.Payload) != "still works" {
		t.Fatalf("b got %+v", p)
	}
}

func TestUnauthorized(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	e := newEnv(t, 0)
	c, err := NewClient(e.url, "bogus", discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.runOnce(ctx); err == nil {
		t.Fatal("connected with a bogus token")
	}
}

func TestReconnectReplacesOldConnection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := newEnv(t, 0)
	b, _ := e.client(t, ctx, 2)
	a1ctx, a1cancel := context.WithCancel(ctx)
	_, ka := e.client(t, a1ctx, 1)
	a2, _ := e.client(t, ctx, 1) // same token again
	a1cancel()

	if err := b.Send(ctx, ka, []byte("to newest")); err != nil {
		t.Fatal(err)
	}
	if p := recv(t, a2); string(p.Payload) != "to newest" {
		t.Fatalf("a2 got %+v", p)
	}
}

func TestRateLimitDrops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := newEnv(t, 1) // 1 byte/s: only the initial burst passes
	a, _ := e.client(t, ctx, 1)
	b, kb := e.client(t, ctx, 2)

	payload := make([]byte, 1000)
	sent := (MaxPayload+headerLen)/len(payload) + 20
	for range sent {
		if err := a.Send(ctx, kb, payload); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	timeout := time.After(time.Second)
loop:
	for {
		select {
		case <-b.Recv():
			got++
		case <-timeout:
			break loop
		}
	}
	if got == 0 || got >= sent {
		t.Fatalf("received %d of %d packets; want some but not all", got, sent)
	}
}

func TestPrune(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := newEnv(t, 0)
	_, ka := e.client(t, ctx, 1)
	_, kb := e.client(t, ctx, 2)
	waitConnected := func(k wgkey.Key) {
		t.Helper()
		for range 200 {
			if e.srv.Connected(k) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("%v never connected", k)
	}
	waitConnected(ka)
	waitConnected(kb)
	e.srv.Prune(func(k wgkey.Key) bool { return k == kb })
	if e.srv.Connected(ka) {
		t.Fatal("pruned node still connected")
	}
	if !e.srv.Connected(kb) {
		t.Fatal("kept node was disconnected")
	}
}
