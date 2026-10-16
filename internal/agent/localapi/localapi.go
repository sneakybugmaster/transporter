// Package localapi is the agent's local control socket, used by the CLI.
package localapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent/engine"
)

// SocketName is the socket's file name inside the state directory.
const SocketName = "transporter.sock"

// Status is what GET /v0/status returns.
type Status struct {
	Coordinator string        `json:"coordinator"`
	NodeID      string        `json:"nodeID"`
	Engine      engine.Status `json:"engine"`
	Error       string        `json:"error,omitempty"`
}

// Backend provides the data the API serves.
type Backend interface {
	Status() Status
	Shutdown()
}

// Serve listens on the unix socket at path until ctx is cancelled.
func Serve(ctx context.Context, path string, b Backend) error {
	_ = os.Remove(path) // stale socket from a previous run
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(b.Status())
	})
	mux.HandleFunc("POST /v0/down", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		go b.Shutdown()
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		_ = os.Remove(path)
		return nil
	}
	return err
}

// Client talks to a running agent.
type Client struct {
	hc *http.Client
}

// NewClient returns a client for the agent socket at path.
func NewClient(path string) *Client {
	return &Client{hc: &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}},
	}}
}

// Status fetches the agent status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	resp, err := c.do(ctx, http.MethodGet, "/v0/status")
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	return st, json.NewDecoder(resp.Body).Decode(&st)
}

// Down asks the agent to disconnect and exit.
func (c *Client) Down(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodPost, "/v0/down")
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Client) do(ctx context.Context, method, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://agent"+path, http.NoBody)
	if err != nil {
		return nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent not running? %w", err)
	}
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("agent: %s: %s", resp.Status, body)
	}
	return resp, nil
}
