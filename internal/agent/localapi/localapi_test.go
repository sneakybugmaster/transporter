package localapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent/engine"
)

type fakeBackend struct{ down chan struct{} }

func (f *fakeBackend) Status() Status {
	return Status{Coordinator: "http://c", NodeID: "n1", Engine: engine.Status{Name: "alpha"}}
}
func (f *fakeBackend) Shutdown() { close(f.down) }

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
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, %v", fi.Mode(), err)
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
