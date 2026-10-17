package adminapi

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
)

func TestAPITokens(t *testing.T) {
	e := newEnv(t)
	e.setup()

	var created APITokenCreated
	r := e.do(e.c, "POST", "/tokens", APITokenCreate{Description: ptr("ci"), TtlSeconds: 3600})
	e.expect(r, 201)
	r.decode(t, &created)
	if !strings.HasPrefix(created.Secret, store.APITokenPrefix) || created.Token.Admin != "admin" || created.Token.ExpiresAt == nil {
		t.Fatalf("created = %+v", created)
	}
	bearer := []string{"Authorization", "Bearer " + created.Secret}

	anon := &http.Client{} // no cookies
	e.expect(e.do(anon, "GET", "/nodes", nil, bearer...), 200)
	e.expect(e.do(anon, "PATCH", "/settings", SettingsUpdate{KeyExpiryDays: ptr(30)}, bearer...), 200)
	// A token cannot mint tokens or change the password.
	e.expect(e.do(anon, "POST", "/tokens", APITokenCreate{}, bearer...), 403)
	e.expect(e.do(anon, "GET", "/tokens", nil, bearer...), 403)
	e.expect(e.do(anon, "POST", "/auth/password", PasswordChange{CurrentPassword: testPassword, NewPassword: "something else 1"}, bearer...), 403)
	e.expect(e.do(anon, "GET", "/nodes", nil, "Authorization", "Bearer tpa_wrong"), 401)

	var audit []AuditEntry
	e.do(e.c, "GET", "/audit?limit=1", nil).decode(t, &audit)
	if !strings.Contains(audit[0].Actor, "API token "+created.Token.Id) {
		t.Fatalf("token change audited as %q", audit[0].Actor)
	}
	var list []APIToken
	e.do(e.c, "GET", "/tokens", nil).decode(t, &list)
	if len(list) != 1 || list[0].LastUsed == nil {
		t.Fatalf("tokens = %+v", list)
	}
	e.expect(e.do(e.c, "DELETE", "/tokens/"+created.Token.Id, nil), 204)
	e.expect(e.do(anon, "GET", "/nodes", nil, bearer...), 401)
}

func TestKeyExpirySettings(t *testing.T) {
	e := newEnv(t)
	e.setup()
	var st Settings
	r := e.do(e.c, "PATCH", "/settings", SettingsUpdate{KeyExpiryDays: ptr(90)})
	e.expect(r, 200)
	r.decode(t, &st)
	if st.KeyExpiryDays != 90 {
		t.Fatalf("settings = %+v", st)
	}
	e.expect(e.do(e.c, "PATCH", "/settings", SettingsUpdate{KeyExpiryDays: ptr(-1)}), 400)

	n := e.registerNodes("alpha")[0]
	var node Node
	r = e.do(e.c, "PATCH", "/nodes/"+n.ID, NodeUpdate{KeyExpiryDisabled: ptr(true)})
	e.expect(r, 200)
	r.decode(t, &node)
	if !node.KeyExpiryDisabled || node.ExpiresAt != nil {
		t.Fatalf("exempt node = %+v", node)
	}
	r = e.do(e.c, "PATCH", "/nodes/"+n.ID, NodeUpdate{KeyExpiryDisabled: ptr(false)})
	r.decode(t, &node)
	if node.ExpiresAt == nil || time.Until(*node.ExpiresAt) < 89*24*time.Hour {
		t.Fatalf("re-subjected node = %+v", node)
	}
	r = e.do(e.c, "PATCH", "/nodes/"+n.ID, NodeUpdate{ExpireNow: ptr(true)})
	r.decode(t, &node)
	if node.ExpiresAt == nil || time.Until(*node.ExpiresAt) > 0 {
		t.Fatalf("expired node = %+v", node)
	}
	e.expect(e.do(e.c, "PATCH", "/nodes/"+n.ID, NodeUpdate{ExpireNow: ptr(true), KeyExpiryDisabled: ptr(true)}), 400)
}

// fakeIdP is a minimal OpenID Connect provider issuing signed ID tokens.
type fakeIdP struct {
	*httptest.Server
	key    *rsa.PrivateKey
	email  string
	mu     sync.Mutex
	codes  map[string]authReq
	sub    string
	verify bool
}

type authReq struct{ nonce, challenge, redirect string }

func newIdP(t *testing.T, email string) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key, email: email, codes: map[string]authReq{}, sub: "user-1", verify: true}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.URL, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token",
			"jwks_uri": p.URL + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		code := "code-" + q.Get("state")[:8]
		p.mu.Lock()
		p.codes[code] = authReq{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		ar, ok := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != ar.challenge {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		claims, _ := json.Marshal(map[string]any{
			"iss": p.URL, "sub": p.sub, "aud": "transporter", "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "nonce": ar.nonce, "email": p.email, "email_verified": p.verify,
		})
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		jws, _ := signer.Sign(claims)
		idt, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt, "expires_in": 3600})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

// ssoLogin walks the browser flow and returns where it ended.
func (e *env) ssoLogin(c *http.Client) *url.URL {
	e.t.Helper()
	var last *url.URL
	c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		last = req.URL
		if req.URL.Path == "/" || req.URL.Path == "/login" {
			return http.ErrUseLastResponse // the console itself is not served here
		}
		return nil
	}
	res, err := c.Get(e.srv.URL + BasePath + "/auth/oidc/login")
	if err != nil {
		e.t.Fatal(err)
	}
	_ = res.Body.Close()
	return last
}

func TestOIDCLogin(t *testing.T) {
	idp := newIdP(t, "Ana@Example.com")
	e := newEnvOpts(t, Options{SetupCode: testCode, OIDC: &OIDCConfig{
		Issuer: "", ClientID: "transporter", ClientSecret: "s3cret", Allowed: []string{"@example.com"}, Name: "Example",
	}})
	e.setup()
	// The issuer is only known once the fake provider runs.
	srv := e.api()
	srv.oidc.cfg.Issuer = idp.URL

	var m AuthMethods
	e.do(newClient(t), "GET", "/auth/methods", nil).decode(t, &m)
	if !m.Oidc || m.OidcName == nil || *m.OidcName != "Example" {
		t.Fatalf("methods = %+v", m)
	}

	browser := newClient(t)
	if end := e.ssoLogin(browser); end == nil || end.Path != "/" {
		t.Fatalf("sign-in ended at %v", end)
	}
	var me Me
	r := e.do(browser, "GET", "/auth/me", nil)
	e.expect(r, 200)
	r.decode(t, &me)
	if me.Username != "ana@example.com" || me.HasPassword {
		t.Fatalf("me = %+v", me)
	}
	// SSO admins cannot sign in with a password.
	e.expect(e.do(newClient(t), "POST", "/auth/login", LoginRequest{Username: "ana@example.com", Password: ""}), 401)

	// Not allowed, and unverified addresses, end on the login page.
	idp.email, idp.sub = "eve@evil.test", "user-2"
	if end := e.ssoLogin(newClient(t)); end == nil || end.Path != "/login" || !strings.Contains(end.Query().Get("error"), "not allowed") {
		t.Fatalf("disallowed sign-in ended at %v", end)
	}
	idp.email, idp.verify = "bob@example.com", false
	if end := e.ssoLogin(newClient(t)); end == nil || !strings.Contains(end.Query().Get("error"), "not verified") {
		t.Fatalf("unverified sign-in ended at %v", end)
	}
	// An existing password admin of the same name is never taken over.
	idp.email, idp.verify, idp.sub = "admin@example.com", true, "user-3"
	if _, err := e.store.CreateAdmin(context.Background(), "admin@example.com", "long enough password"); err != nil {
		t.Fatal(err)
	}
	if end := e.ssoLogin(newClient(t)); end == nil || !strings.Contains(end.Query().Get("error"), "already exists") {
		t.Fatalf("conflicting sign-in ended at %v", end)
	}
	// A callback without the browser's state cookie is refused.
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).
		Get(e.srv.URL + BasePath + "/auth/oidc/callback?code=x&state=y")
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if loc := res.Header.Get("Location"); !strings.Contains(loc, "another+browser") {
		t.Fatalf("forged callback redirected to %q", loc)
	}
}
