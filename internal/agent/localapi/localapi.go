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
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sneakybugmaster/transporter/internal/agent/engine"
	"github.com/sneakybugmaster/transporter/internal/agent/pingsvc"
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
	// Ping probes target (a peer name or mesh IP), calling fn per result,
	// and returns the address it resolved target to.
	Ping(ctx context.Context, target string, count int, timeout time.Duration, fn func(pingsvc.Result)) (netip.Addr, error)
}

// PingResult is one line of the GET /v0/ping response.
type PingResult struct {
	Addr  string  `json:"addr,omitempty"` // first line only
	Seq   uint32  `json:"seq,omitempty"`
	RTTMs float64 `json:"rttMs,omitempty"`
	Error string  `json:"error,omitempty"`
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
	// On Windows the socket inherits the state directory's ACL instead.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			_ = ln.Close()
			return err
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v0/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(b.Status())
	})
	mux.HandleFunc("GET /v0/ping", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		count, _ := strconv.Atoi(q.Get("count"))
		timeout, _ := time.ParseDuration(q.Get("timeout"))
		if count < 1 || count > 1000 || timeout <= 0 {
			http.Error(w, "count must be 1-1000 and timeout positive", http.StatusBadRequest)
			return
		}
		// Results stream as JSON lines so the CLI can print them live.
		w.Header().Set("Content-Type", "application/x-ndjson")
		rc := http.NewResponseController(w)
		enc := json.NewEncoder(w)
		started := false
		addr, err := b.Ping(r.Context(), q.Get("target"), count, timeout, func(res pingsvc.Result) {
			line := PingResult{Seq: res.Seq, RTTMs: float64(res.RTT.Microseconds()) / 1000}
			if res.Err != nil {
				line.Error = res.Err.Error()
			}
			_ = enc.Encode(line)
			_ = rc.Flush()
			started = true
		})
		if err != nil && !started {
			_ = enc.Encode(PingResult{Error: err.Error()})
			return
		}
		_ = enc.Encode(PingResult{Addr: addr.String()})
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

// Ping asks the agent to probe target, calling fn for each result line as
// it arrives. The final line carries the resolved address; a line with only
// an error means the ping could not start.
func (c *Client) Ping(ctx context.Context, target string, count int, timeout time.Duration, fn func(PingResult)) error {
	q := url.Values{"target": {target}, "count": {strconv.Itoa(count)}, "timeout": {timeout.String()}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/v0/ping?"+q.Encode(), http.NoBody)
	if err != nil {
		return err
	}
	hc := *c.hc
	hc.Timeout = 0 // pings can take as long as the caller asks
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("agent not running? %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("agent: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var line PingResult
		if err := dec.Decode(&line); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		fn(line)
	}
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
