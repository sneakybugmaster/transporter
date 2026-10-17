package localapi

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent/engine"
	"github.com/sneakybugmaster/transporter/internal/agent/pingsvc"
)

type fakeBackend struct{ down chan struct{} }

func (f *fakeBackend) Status() Status {
	return Status{Coordinator: "http://c", NodeID: "n1", Engine: engine.Status{Name: "alpha"}}
}
func (f *fakeBackend) Shutdown() { close(f.down) }

func (f *fakeBackend) Ping(_ context.Context, target string, count int, _ time.Duration, fn func(pingsvc.Result)) (netip.Addr, error) {
	if target != "bravo" {
		return netip.Addr{}, errors.New("unknown peer")
	}
	for i := 1; i <= count; i++ {
		fn(pingsvc.Result{Seq: uint32(i), RTT: time.Duration(i) * time.Millisecond}) //nolint:gosec // small test values
	}
	return netip.MustParseAddr("100.64.0.2"), nil
}

func TestLocalAPI(t *testing.T) {
	// Unix socket paths are limited to ~100 bytes; t.TempDir can exceed that.
	dir, err := os.MkdirTemp("", "tla")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, SocketName)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &fakeBackend{down: make(chan struct{})}
	errc := make(chan error, 1)
	go func() { errc <- Serve(ctx, path, b) }()

	c := NewClient(path)
	var st Status
	for i := 0; ; i++ {
		st, err = c.Status(ctx)
		if err == nil || i > 50 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || st.Engine.Name != "alpha" || st.NodeID != "n1" {
		t.Fatalf("status = %+v, %v", st, err)
	}
	if fi, err := os.Stat(path); runtime.GOOS != "windows" && (err != nil || fi.Mode().Perm() != 0o600) {
		t.Fatalf("socket mode = %v, %v", fi.Mode(), err)
	}

	var lines []PingResult
	if err := c.Ping(ctx, "bravo", 2, time.Second, func(l PingResult) { lines = append(lines, l) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 3 || lines[0].Seq != 1 || lines[1].RTTMs != 2 || lines[2].Addr != "100.64.0.2" {
		t.Fatalf("ping lines = %+v", lines)
	}
	lines = nil
	if err := c.Ping(ctx, "nobody", 1, time.Second, func(l PingResult) { lines = append(lines, l) }); err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0].Error != "unknown peer" {
		t.Fatalf("ping lines = %+v", lines)
	}
	if err := c.Ping(ctx, "bravo", 0, time.Second, func(PingResult) {}); err == nil {
		t.Fatal("count 0 accepted")
	}

	if err := c.Down(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.down:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown not called")
	}

	cancel()
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(path).Status(context.Background()); err == nil {
		t.Fatal("status succeeded after server stopped")
	}
}
