// Package controlclient talks to the coordinator's control service.
package controlclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"connectrpc.com/connect"

	"github.com/sneakybugmaster/transporter/internal/netns"
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
		DialContext:           netns.DialContext, // bypasses an exit node's tunnel
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
func (c *Client) Watch(ctx context.Context, token string, msg *controlv1.WatchNetmapRequest, fn func(*controlv1.WatchNetmapResponse) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	idle := time.AfterFunc(idleTimeout, cancel)
	defer idle.Stop()

	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+token)
	stream, err := c.rpc.WatchNetmap(ctx, req)
	if err != nil {
		return wrap(err)
	}
	defer stream.Close()
	for stream.Receive() {
		idle.Reset(idleTimeout)
		if stream.Msg().GetKeepAlive() {
			continue // nothing changed
		}
		if err := fn(stream.Msg()); err != nil {
			return err
		}
	}
	if err := stream.Err(); err != nil {
		return wrap(err)
	}
	return errors.New("netmap stream closed by coordinator")
}

// UpdateEndpoints replaces the endpoints the coordinator advertises for this node.
func (c *Client) UpdateEndpoints(ctx context.Context, token string, endpoints []string) error {
	req := connect.NewRequest(&controlv1.UpdateEndpointsRequest{Endpoints: endpoints})
	req.Header().Set("Authorization", "Bearer "+token)
	_, err := c.rpc.UpdateEndpoints(ctx, req)
	return wrap(err)
}

// ReportStatus reports how this node reaches its peers.
func (c *Client) ReportStatus(ctx context.Context, token string, peers []*controlv1.PeerPath) error {
	req := connect.NewRequest(&controlv1.ReportStatusRequest{Peers: peers})
	req.Header().Set("Authorization", "Bearer "+token)
	_, err := c.rpc.ReportStatus(ctx, req)
	return wrap(err)
}

func wrap(err error) error {
	if connect.CodeOf(err) == connect.CodeUnauthenticated {
		return fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	return err
}
