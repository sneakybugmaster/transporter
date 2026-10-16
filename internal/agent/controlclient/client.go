// Package controlclient talks to the coordinator's control service.
package controlclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"

	controlv1 "github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1"
	"github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1/controlv1connect"
)

// idleTimeout bounds how long a netmap stream may stay silent; the
// coordinator sends at least every 30 seconds.
const idleTimeout = 90 * time.Second

// ErrUnauthenticated means the coordinator rejected the auth key or token.
var ErrUnauthenticated = errors.New("unauthenticated")

// Client is a control-plane client.
type Client struct {
	rpc controlv1connect.ControlServiceClient
}

// New returns a client for the coordinator at baseURL (http or https).
func New(baseURL string) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid coordinator URL %q: want http(s)://host[:port]", baseURL)
	}
	hc := &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     true,
	}}
	return &Client{rpc: controlv1connect.NewControlServiceClient(hc, strings.TrimRight(baseURL, "/"))}, nil
}

// Register enrolls this node.
func (c *Client) Register(ctx context.Context, req *controlv1.RegisterRequest) (*controlv1.RegisterResponse, error) {
	resp, err := c.rpc.Register(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, wrap(err)
	}
	return resp.Msg, nil
}

// Watch opens a netmap stream and calls fn for every netmap until the stream
// ends, ctx is cancelled, or fn returns an error.
func (c *Client) Watch(ctx context.Context, token string, endpoints []string, fn func(*controlv1.WatchNetmapResponse) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(idleTimeout, cancel)
	defer idle.Stop()

	req := connect.NewRequest(&controlv1.WatchNetmapRequest{Endpoints: endpoints})
	req.Header().Set("Authorization", "Bearer "+token)
	stream, err := c.rpc.WatchNetmap(ctx, req)
	if err != nil {
		return wrap(err)
	}
	defer stream.Close()
	for stream.Receive() {
		idle.Reset(idleTimeout)
		if err := fn(stream.Msg()); err != nil {
			return err
		}
	}
	if err := stream.Err(); err != nil {
		return wrap(err)
	}
	return errors.New("netmap stream closed by coordinator")
}

func wrap(err error) error {
	if connect.CodeOf(err) == connect.CodeUnauthenticated {
		return fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	return err
}
