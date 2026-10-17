package relay

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/sneakybugmaster/transporter/internal/netns"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

// Packet is a payload received from another node through the relay.
type Packet struct {
	From    wgkey.Key
	Payload []byte
}

// Client keeps a connection to the relay open, reconnecting as needed.
type Client struct {
	url   string
	token string
	log   *slog.Logger
	recv  chan Packet

	mu   sync.Mutex
	conn *websocket.Conn
}

// NewClient returns a client for the relay on the coordinator at baseURL.
// Received packets are delivered on Recv().
func NewClient(baseURL, token string, log *slog.Logger) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/") + Path)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return nil, errors.New("relay: coordinator URL must be http or https")
	}
	return &Client{url: u.String(), token: token, log: log, recv: make(chan Packet, 256)}, nil
}

// Recv returns the channel received packets are delivered on.
func (c *Client) Recv() <-chan Packet { return c.recv }

// Connected reports whether the client currently holds a connection.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn != nil
}

// Send forwards payload to the node with key dst. It fails fast when not
// connected rather than queueing: callers resend (WireGuard retransmits).
func (c *Client) Send(ctx context.Context, dst wgkey.Key, payload []byte) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return errors.New("relay: not connected")
	}
	ctx, cancel := context.WithTimeout(ctx, writeTimeout)
	defer cancel()
	return conn.Write(ctx, websocket.MessageBinary, encode(frameSend, dst, payload))
}

// Run maintains the connection until ctx is cancelled.
func (c *Client) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		c.log.Debug("relay connection lost", "err", err, "retry", backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(dialCtx, c.url, &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: &http.Transport{
			Proxy:       http.ProxyFromEnvironment,
			DialContext: netns.DialContext, // never through the tunnel it carries
		}},
		HTTPHeader: http.Header{"Authorization": {"Bearer " + c.token}},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		return err
	}
	conn.SetReadLimit(MaxPayload + headerLen)
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	c.log.Debug("relay connected")
	defer func() {
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
		_ = conn.CloseNow()
	}()

	for {
		typ, msg, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageBinary {
			continue
		}
		src, payload, err := decode(msg, frameRecv)
		if err != nil {
			continue
		}
		select {
		case c.recv <- Packet{From: src, Payload: payload}:
		default: // consumer is behind: drop
		}
	}
}
