package adminapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
)

// OIDCConfig enables single sign-on for admins through an OpenID Connect
// provider (Google, Microsoft Entra ID, Okta, Keycloak, Authentik, ...).
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL is registered with the provider; empty derives it from
	// the public URL setting or the request.
	RedirectURL string
	// Allowed lists who may sign in: exact email addresses, or "@domain"
	// for a whole domain. Empty allows nobody.
	Allowed []string
	// Name labels the sign-in button, e.g. "Google".
	Name string
}

const (
	oidcCookie   = "tp_oidc"
	oidcLoginTTL = 10 * time.Minute
	maxPending   = 1000
)

type oidcState struct {
	cfg OIDCConfig

	mu       sync.Mutex
	provider *oidc.Provider // discovered on first use
	pending  map[string]pendingLogin
}

type pendingLogin struct {
	nonce, verifier, redirect string
	expires                   time.Time
}

func newOIDC(cfg *OIDCConfig) *oidcState {
	if cfg == nil {
		return nil
	}
	return &oidcState{cfg: *cfg, pending: map[string]pendingLogin{}}
}

// discover fetches the provider's configuration, retrying on later logins
// if the provider was unreachable.
func (o *oidcState) discover(ctx context.Context) (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, o.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", o.cfg.Issuer, err)
	}
	o.provider = p
	return p, nil
}

func (o *oidcState) allowed(email string) bool {
	email = strings.ToLower(email)
	for _, a := range o.cfg.Allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == email || (strings.HasPrefix(a, "@") && strings.HasSuffix(email, a)) {
			return true
		}
	}
	return false
}

func randomString() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) oauthConfig(r *http.Request, p *oidc.Provider) oauth2.Config {
	redirect := s.oidc.cfg.RedirectURL
	if redirect == "" {
		base, _ := s.store.Setting(r.Context(), store.SettingPublicURL)
		if base == "" {
			scheme := "http"
			if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
				scheme = "https"
			}
			base = scheme + "://" + r.Host
		}
		redirect = strings.TrimRight(base, "/") + BasePath + "/auth/oidc/callback"
	}
	return oauth2.Config{
		ClientID:     s.oidc.cfg.ClientID,
		ClientSecret: s.oidc.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  redirect,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

func (s *Server) OidcLogin(w http.ResponseWriter, r *http.Request) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "single sign-on is not configured")
		return
	}
	if !s.allow(r) {
		writeError(w, http.StatusTooManyRequests, "too many attempts, wait a minute")
		return
	}
	p, err := s.oidc.discover(r.Context())
	if err != nil {
		s.log.Error("OIDC", "err", err)
		loginError(w, r, "the identity provider is unreachable")
		return
	}
	state, nonce, verifier := randomString(), randomString(), oauth2.GenerateVerifier()
	cfg := s.oauthConfig(r, p)
	s.oidc.mu.Lock()
	now := time.Now()
	for k, v := range s.oidc.pending {
		if now.After(v.expires) {
			delete(s.oidc.pending, k)
		}
	}
	if len(s.oidc.pending) >= maxPending {
		s.oidc.mu.Unlock()
		writeError(w, http.StatusTooManyRequests, "too many sign-ins in progress")
		return
	}
	s.oidc.pending[state] = pendingLogin{nonce: nonce, verifier: verifier, redirect: cfg.RedirectURL, expires: now.Add(oidcLoginTTL)}
	s.oidc.mu.Unlock()

	// The cookie ties the callback to this browser, so nobody can complete
	// a sign-in they started in someone else's browser. It must survive the
	// cross-site redirect back from the provider, hence SameSite=Lax.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure set for HTTPS, as for sessions
		Name:     oidcCookie,
		Value:    state,
		Path:     BasePath + "/auth/oidc/",
		MaxAge:   int(oidcLoginTTL.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https",
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, cfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

func (s *Server) OidcCallback(w http.ResponseWriter, r *http.Request, params OidcCallbackParams) {
	if s.oidc == nil {
		writeError(w, http.StatusNotFound, "single sign-on is not configured")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Path: BasePath + "/auth/oidc/", MaxAge: -1}) //nolint:gosec // deletion
	if params.Error != nil {
		loginError(w, r, "the identity provider refused the sign-in: "+*params.Error)
		return
	}
	c, err := r.Cookie(oidcCookie)
	if err != nil || params.State == nil || params.Code == nil || c.Value != *params.State {
		loginError(w, r, "sign-in expired or was started in another browser; try again")
		return
	}
	s.oidc.mu.Lock()
	pl, ok := s.oidc.pending[*params.State]
	delete(s.oidc.pending, *params.State)
	s.oidc.mu.Unlock()
	if !ok || time.Now().After(pl.expires) {
		loginError(w, r, "sign-in expired; try again")
		return
	}

	ctx := r.Context()
	p, err := s.oidc.discover(ctx)
	if err != nil {
		loginError(w, r, "the identity provider is unreachable")
		return
	}
	cfg := s.oauthConfig(r, p)
	cfg.RedirectURL = pl.redirect
	tok, err := cfg.Exchange(ctx, *params.Code, oauth2.VerifierOption(pl.verifier))
	if err != nil {
		s.log.Warn("OIDC code exchange", "err", err)
		loginError(w, r, "the identity provider rejected the sign-in")
		return
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		loginError(w, r, "the identity provider sent no ID token")
		return
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: s.oidc.cfg.ClientID}).Verify(ctx, raw)
	if err != nil || idt.Nonce != pl.nonce {
		s.log.Warn("OIDC ID token", "err", err)
		loginError(w, r, "invalid ID token")
		return
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
	}
	if err := idt.Claims(&claims); err != nil || claims.Email == "" {
		loginError(w, r, "the identity provider did not share an email address")
		return
	}
	if claims.EmailVerified != nil && !*claims.EmailVerified {
		loginError(w, r, claims.Email+" is not verified with the identity provider")
		return
	}
	if !s.oidc.allowed(claims.Email) {
		s.log.Warn("OIDC sign-in refused", "email", claims.Email)
		loginError(w, r, claims.Email+" is not allowed to administer this coordinator")
		return
	}
	a, err := s.store.OIDCAdmin(ctx, idt.Issuer+" "+idt.Subject, strings.ToLower(claims.Email))
	if errors.Is(err, store.ErrConflict) {
		loginError(w, r, "a password admin named "+claims.Email+" already exists; rename it to sign in with SSO")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	token, expires, err := s.store.CreateSession(ctx, a.ID, sessionTTL)
	if err != nil {
		s.internal(w, err)
		return
	}
	cookie := sessionCookie(r, token) //nolint:gosec // see sessionCookie
	cookie.Expires = expires
	http.SetCookie(w, cookie)
	s.auditAs(ctx, a.Username, "admin.sso_login", "", idt.Issuer)
	http.Redirect(w, r, "/", http.StatusFound)
}

// loginError sends the browser back to the login page with a message.
func loginError(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(msg), http.StatusFound)
}

func (s *Server) GetAuthMethods(w http.ResponseWriter, _ *http.Request) {
	m := AuthMethods{Password: true, Oidc: s.oidc != nil}
	if s.oidc != nil {
		name := s.oidc.cfg.Name
		if name == "" {
			name = "single sign-on"
		}
		m.OidcName = &name
	}
	writeJSON(w, http.StatusOK, m)
}
