package relay

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

const (
	sendQueue    = 256
	pingInterval = 30 * time.Second
	writeTimeout = 10 * time.Second
)

// Authenticator maps a bearer token to the WireGuard key of the node it
// belongs to.
type Authenticator func(ctx context.Context, token string) (wgkey.Key, error)

// Server is the relay endpoint.
type Server struct {
	auth  Authenticator
	log   *slog.Logger
	rate  rate.Limit
	burst int

	mu      sync.Mutex
	clients map[wgkey.Key]*client
}

type client struct {
	key  wgkey.Key
	send chan []byte
	done chan struct{}
	once sync.Once
}

func (c *client) close() { c.once.Do(func() { close(c.done) }) }

// NewServer returns a relay that lets each node send bytesPerSec on average
// (with bursts up to burst bytes). Zero bytesPerSec means unlimited.
func NewServer(auth Authenticator, bytesPerSec, burst int, log *slog.Logger) *Server {
	lim := rate.Limit(bytesPerSec)
	if bytesPerSec <= 0 {
		lim = rate.Inf
	}
	burst = max(burst, MaxPayload+headerLen)
	return &Server{auth: auth, log: log, rate: lim, burst: burst, clients: map[wgkey.Key]*client{}}
}

// Connected reports whether a node with key holds a relay connection.
func (s *Server) Connected(key wgkey.Key) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.clients[key]
	return ok
}

// ServeHTTP upgrades the request to a relay connection.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		http.Error(w, "missing bearer token", http.StatusUnauthorized)
		return
	}
	key, err := s.auth(r.Context(), token)
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return // Accept already wrote the error response
	}
	conn.SetReadLimit(MaxPayload + headerLen)

	c := &client{key: key, send: make(chan []byte, sendQueue), done: make(chan struct{})}
	s.mu.Lock()
	if old := s.clients[key]; old != nil {
		old.close() // a node reconnecting replaces its previous connection
	}
	s.clients[key] = c
	s.mu.Unlock()
	log := s.log.With("node", key.String())
	log.Debug("relay client connected")

	ctx, cancel := context.WithCancel(r.Context())
	defer func() {
		cancel()
		s.mu.Lock()
		if s.clients[key] == c {
			delete(s.clients, key)
		}
		s.mu.Unlock()
		c.close()
		_ = conn.CloseNow()
		log.Debug("relay client disconnected")
	}()

	go s.writeLoop(ctx, cancel, conn, c)

	lim := rate.NewLimiter(s.rate, s.burst)
	for {
		typ, msg, err := conn.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		dst, payload, err := decode(msg, frameSend)
		if err != nil {
			continue
		}
		if !lim.AllowN(time.Now(), len(payload)) {
			continue // over the rate limit: drop, like a congested link
		}
		s.forward(key, dst, payload)
	}
}

func (s *Server) forward(src, dst wgkey.Key, payload []byte) {
	s.mu.Lock()
	d := s.clients[dst]
	s.mu.Unlock()
	if d == nil {
		return
	}
	select {
	case d.send <- encode(frameRecv, src, payload):
	default: // receiver is not keeping up: drop
	}
}

func (s *Server) writeLoop(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, c *client) {
	defer cancel()
	ping := time.NewTicker(pingInterval)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			_ = conn.Close(websocket.StatusGoingAway, "replaced by a newer connection")
			return
		case <-ping.C:
			pctx, pcancel := context.WithTimeout(ctx, writeTimeout)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}
		case msg := <-c.send:
			wctx, wcancel := context.WithTimeout(ctx, writeTimeout)
			err := conn.Write(wctx, websocket.MessageBinary, msg)
			wcancel()
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					s.log.Debug("relay write", "err", err)
				}
				return
			}
		}
	}
}
