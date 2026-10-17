// Package adminapi implements the administration API used by the web UI.
// Types and routing are generated from api/openapi.yaml (api.gen.go).
package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/sneakybugmaster/transporter/internal/coordinator/control"
	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
	"github.com/sneakybugmaster/transporter/internal/version"
	"github.com/sneakybugmaster/transporter/internal/wgkey"
)

const (
	// BasePath is where the API is mounted.
	BasePath   = "/api/v1"
	cookieName = "tp_session"
	sessionTTL = 7 * 24 * time.Hour
	maxBody    = 64 << 10
	maxKeyTTL  = 365 * 24 * time.Hour
)

// publicOps lists the operations reachable without a session. It must match
// the operations marked `security: []` in api/openapi.yaml (a test checks).
var publicOps = map[string]bool{
	"GET " + BasePath + "/version":     true,
	"GET " + BasePath + "/setup":       true,
	"POST " + BasePath + "/setup":      true,
	"POST " + BasePath + "/auth/login": true,
}

// Server implements ServerInterface.
type Server struct {
	store *store.Store
	ctl   *control.Service
	log   *slog.Logger

	mu        sync.Mutex
	setupCode string // empty once setup is done

	limMu    sync.Mutex
	limiters map[string]*rate.Limiter
}

var _ ServerInterface = (*Server)(nil)

// New returns the API server. If no admin exists yet it generates a one-time
// setup code (or uses setupCode if non-empty) and logs it: whoever completes
// setup must be able to read the coordinator's log.
func New(ctx context.Context, st *store.Store, ctl *control.Service, setupCode string, log *slog.Logger) (*Server, error) {
	s := &Server{store: st, ctl: ctl, log: log, limiters: map[string]*rate.Limiter{}}
	n, err := st.AdminCount(ctx)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		if setupCode == "" {
			setupCode = newSetupCode()
		}
		s.setupCode = setupCode
		log.Warn("first-run setup: open the web UI and enter this setup code", "setupCode", setupCode)
	}
	return s, nil
}

func newSetupCode() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	s := base32.StdEncoding.EncodeToString(b) // 16 chars
	return s[:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

// Handler returns the API handler, to be mounted at BasePath + "/".
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(BasePath+"/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	HandlerWithOptions(s, StdHTTPServerOptions{
		BaseURL:    BasePath,
		BaseRouter: mux,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeError(w, http.StatusBadRequest, err.Error())
		},
	})
	return s.middleware(mux)
}

type ctxKey int

const (
	adminKey ctxKey = iota
	tokenKey
)

// middleware enforces sessions on non-public operations and blocks
// cross-site requests that change state.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if !safeMethod(r.Method) {
			if err := checkSameOrigin(r); err != nil {
				writeError(w, http.StatusForbidden, err.Error())
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		}
		if publicOps[r.Method+" "+r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "not logged in")
			return
		}
		admin, err := s.store.SessionAdmin(r.Context(), c.Value)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				s.log.Error("session lookup", "err", err)
			}
			writeError(w, http.StatusUnauthorized, "session expired")
			return
		}
		ctx := context.WithValue(r.Context(), adminKey, admin)
		ctx = context.WithValue(ctx, tokenKey, c.Value)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// checkSameOrigin rejects state-changing requests a browser could send from
// another site. Requiring a JSON content type means a cross-site page needs a
// CORS preflight (which we never grant); the Origin check covers the rest.
func checkSameOrigin(r *http.Request) error {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "application/json" {
		return errors.New("requests that change state must use Content-Type: application/json")
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil // not a browser cross-origin request
	}
	u, err := url.Parse(origin)
	if err != nil {
		return errors.New("bad Origin header")
	}
	host := r.Host
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		host = fh
	}
	if !strings.EqualFold(u.Host, host) {
		return errors.New("cross-origin request refused")
	}
	return nil
}

func admin(r *http.Request) store.Admin {
	a, _ := r.Context().Value(adminKey).(store.Admin)
	return a
}

// allow applies a per-client-IP limit to login and setup attempts.
func (s *Server) allow(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	s.limMu.Lock()
	defer s.limMu.Unlock()
	if len(s.limiters) > 10000 {
		s.limiters = map[string]*rate.Limiter{} // crude bound on memory
	}
	l := s.limiters[ip]
	if l == nil {
		l = rate.NewLimiter(rate.Every(6*time.Second), 10) // 10 at once, then 10/min
		s.limiters[ip] = l
	}
	return l.Allow()
}

// sessionCookie is HttpOnly and SameSite=Strict, and Secure whenever the
// request arrived over HTTPS (directly or via a TLS-terminating proxy). It
// cannot always be Secure: browsers would drop it on plain-HTTP deployments.
func sessionCookie(r *http.Request, value string) *http.Cookie {
	return &http.Cookie{ //nolint:gosec // Secure is set for HTTPS, see above
		Name:     cookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteStrictMode,
	}
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, a store.Admin) {
	token, expires, err := s.store.CreateSession(r.Context(), a.ID, sessionTTL)
	if err != nil {
		s.internal(w, err)
		return
	}
	c := sessionCookie(r, token) //nolint:gosec // see sessionCookie
	c.Expires = expires
	http.SetCookie(w, c)
	writeJSON(w, http.StatusOK, Me{Username: a.Username})
}

// --- operations ---------------------------------------------------------------

func (s *Server) GetVersion(w http.ResponseWriter, _ *http.Request) {
	v := version.Get()
	writeJSON(w, http.StatusOK, Version{Version: v.Version, Commit: v.Commit, Date: v.Date, GoVersion: v.GoVersion, Platform: v.Platform})
}

func (s *Server) GetSetup(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	needs := s.setupCode != ""
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, SetupStatus{NeedsSetup: needs})
}

func (s *Server) CompleteSetup(w http.ResponseWriter, r *http.Request) {
	var req SetupRequest
	if !decode(w, r, &req) {
		return
	}
	if !s.allow(r) {
		writeError(w, http.StatusTooManyRequests, "too many attempts, wait a minute")
		return
	}
	s.mu.Lock()
	code := s.setupCode
	s.mu.Unlock()
	if code == "" {
		writeError(w, http.StatusConflict, "setup has already been completed")
		return
	}
	if subtle.ConstantTimeCompare([]byte(normaliseCode(req.SetupCode)), []byte(normaliseCode(code))) != 1 {
		writeError(w, http.StatusForbidden, "wrong setup code: copy it from the coordinator's log")
		return
	}
	publicURL := ""
	if req.PublicURL != nil && strings.TrimSpace(*req.PublicURL) != "" {
		var err error
		if publicURL, err = cleanPublicURL(*req.PublicURL); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	a, err := s.store.CreateFirstAdmin(r.Context(), req.Username, req.Password)
	switch {
	case errors.Is(err, store.ErrSetupDone):
		writeError(w, http.StatusConflict, err.Error())
		return
	case isValidation(err):
		writeError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	s.mu.Lock()
	s.setupCode = ""
	s.mu.Unlock()
	if publicURL != "" {
		if err := s.store.SetSetting(r.Context(), store.SettingPublicURL, publicURL); err != nil {
			s.internal(w, err)
			return
		}
	}
	s.log.Info("setup completed", "admin", a.Username)
	s.startSession(w, r, a)
}

func normaliseCode(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if !decode(w, r, &req) {
		return
	}
	if !s.allow(r) {
		writeError(w, http.StatusTooManyRequests, "too many attempts, wait a minute")
		return
	}
	a, err := s.store.Authenticate(r.Context(), req.Username, req.Password)
	if errors.Is(err, store.ErrInvalidCredentials) {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.startSession(w, r, a)
}

func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
	if tok, ok := r.Context().Value(tokenKey).(string); ok {
		if err := s.store.DeleteSession(r.Context(), tok); err != nil {
			s.internal(w, err)
			return
		}
	}
	c := sessionCookie(r, "") //nolint:gosec // see sessionCookie
	c.MaxAge = -1
	http.SetCookie(w, c)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) GetMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, Me{Username: admin(r).Username})
}

func (s *Server) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req PasswordChange
	if !decode(w, r, &req) {
		return
	}
	tok, _ := r.Context().Value(tokenKey).(string)
	err := s.store.ChangePassword(r.Context(), admin(r).ID, req.CurrentPassword, req.NewPassword, tok)
	switch {
	case errors.Is(err, store.ErrInvalidCredentials):
		writeError(w, http.StatusForbidden, "current password is wrong")
	case isValidation(err):
		writeError(w, http.StatusBadRequest, err.Error())
	case err != nil:
		s.internal(w, err)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) GetStats(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	st := Stats{Nodes: len(nodes)}
	for _, n := range nodes {
		if s.ctl.Online(n.ID) {
			st.Online++
		}
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) ListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]Node, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, s.nodeJSON(n))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) GetNode(w http.ResponseWriter, r *http.Request, id string) {
	n, err := s.store.NodeByID(r.Context(), id)
	if s.storeErr(w, err) {
		return
	}
	writeJSON(w, http.StatusOK, s.nodeJSON(n))
}

func (s *Server) UpdateNode(w http.ResponseWriter, r *http.Request, id string) {
	var req NodeUpdate
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" || len(req.Name) > 63 {
		writeError(w, http.StatusBadRequest, "name must be 1-63 characters")
		return
	}
	n, err := s.store.RenameNode(r.Context(), id, req.Name)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "another node already has that name")
		return
	}
	if s.storeErr(w, err) {
		return
	}
	s.log.Info("node renamed", "id", id, "name", n.Name, "by", admin(r).Username)
	s.ctl.Notify()
	writeJSON(w, http.StatusOK, s.nodeJSON(n))
}

func (s *Server) DeleteNode(w http.ResponseWriter, r *http.Request, id string) {
	if s.storeErr(w, s.store.DeleteNode(r.Context(), id)) {
		return
	}
	s.log.Info("node deleted", "id", id, "by", admin(r).Username)
	s.ctl.Notify() // its stream ends and peers drop it
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) ListAuthKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.ListAuthKeys(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	out := make([]AuthKey, 0, len(keys))
	now := time.Now()
	for _, k := range keys {
		out = append(out, authKeyJSON(k, now))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) CreateAuthKey(w http.ResponseWriter, r *http.Request) {
	var req AuthKeyCreate
	if !decode(w, r, &req) {
		return
	}
	ttl := time.Duration(req.TtlSeconds) * time.Second
	if req.TtlSeconds < 0 || ttl > maxKeyTTL {
		writeError(w, http.StatusBadRequest, "ttlSeconds must be between 0 (never expires) and one year")
		return
	}
	desc := ""
	if req.Description != nil {
		desc = strings.TrimSpace(*req.Description)
	}
	if len(desc) > 200 {
		writeError(w, http.StatusBadRequest, "description is too long")
		return
	}
	k, secret, err := s.store.CreateAuthKey(r.Context(), store.AuthKeyOptions{Description: desc, Reusable: req.Reusable, TTL: ttl})
	if err != nil {
		s.internal(w, err)
		return
	}
	s.log.Info("auth key created", "id", k.ID, "reusable", k.Reusable, "by", admin(r).Username)
	writeJSON(w, http.StatusCreated, AuthKeyCreated{Key: authKeyJSON(k, time.Now()), Secret: secret})
}

func (s *Server) RevokeAuthKey(w http.ResponseWriter, r *http.Request, id string) {
	if s.storeErr(w, s.store.RevokeAuthKey(r.Context(), id)) {
		return
	}
	s.log.Info("auth key revoked", "id", id, "by", admin(r).Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) GetSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.settings(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req SettingsUpdate
	if !decode(w, r, &req) {
		return
	}
	u := ""
	if strings.TrimSpace(req.PublicURL) != "" {
		var err error
		if u, err = cleanPublicURL(req.PublicURL); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if err := s.store.SetSetting(r.Context(), store.SettingPublicURL, u); err != nil {
		s.internal(w, err)
		return
	}
	s.GetSettings(w, r)
}

func (s *Server) settings(ctx context.Context) (Settings, error) {
	u, err := s.store.Setting(ctx, store.SettingPublicURL)
	opts := s.ctl.Options()
	return Settings{
		PublicURL:     u,
		NetworkPrefix: s.ctl.Prefix().String(),
		StunPort:      int(opts.STUNPort),
		RelayEnabled:  opts.RelayEnabled,
		Version:       version.Version,
	}, err
}

// StreamEvents sends a `change` event whenever the mesh changes.
func (s *Server) StreamEvents(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // don't let nginx buffer the stream
	ch, stop := s.ctl.Subscribe()
	defer stop()
	send := func(msg string) bool {
		if _, err := io.WriteString(w, msg); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send("retry: 3000\n\n") {
		return
	}
	keepalive := time.NewTicker(25 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ch:
			if !send("event: change\ndata: {}\n\n") {
				return
			}
		case <-keepalive.C:
			if !send(": keepalive\n\n") {
				return
			}
		}
	}
}

// --- helpers --------------------------------------------------------------

func (s *Server) nodeJSON(n store.Node) Node {
	eps := n.Endpoints
	if eps == nil {
		eps = []string{}
	}
	return Node{
		Id:        n.ID,
		Name:      n.Name,
		Hostname:  n.Hostname,
		Os:        n.OS,
		PublicKey: wgkey.Key(n.WGPublicKey).String(),
		Addresses: []string{n.IPv4.String() + "/32"},
		Endpoints: eps,
		Online:    s.ctl.Online(n.ID),
		LastSeen:  n.LastSeen,
		CreatedAt: n.CreatedAt,
	}
}

func authKeyJSON(k store.AuthKey, now time.Time) AuthKey {
	return AuthKey{
		Id:          k.ID,
		Description: k.Description,
		Reusable:    k.Reusable,
		UsedCount:   k.UsedCount,
		Revoked:     k.Revoked,
		Valid:       k.Valid(now),
		CreatedAt:   k.CreatedAt,
		ExpiresAt:   k.ExpiresAt,
	}
}

func cleanPublicURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("public URL must look like https://mesh.example.com")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func isValidation(err error) bool {
	var ve *store.ValidationError
	return errors.As(err, &ve)
}

func (s *Server) storeErr(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not found")
	default:
		s.internal(w, err)
	}
	return true
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("admin API", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, Error{Error: msg})
}
