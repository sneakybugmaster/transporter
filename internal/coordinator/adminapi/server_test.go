package adminapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sneakybugmaster/transporter/internal/coordinator/control"
	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
)

const (
	testCode     = "ABCD-EFGH-IJKL-MNOP"
	testPassword = "correct horse battery"
)

type env struct {
	t      *testing.T
	srvAPI *Server
	store  *store.Store
	ctl    *control.Service
	srv    *httptest.Server
	c      *http.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvOpts(t, Options{SetupCode: testCode})
}

func newEnvOpts(t *testing.T, opts Options) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenMemory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctl := control.NewService(st, netip.MustParsePrefix("100.64.0.0/10"), control.Options{STUNPort: 3478, RelayEnabled: true}, log)
	api, err := New(ctx, st, ctl, opts, log)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(BasePath+"/", api.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{t: t, srvAPI: api, store: st, ctl: ctl, srv: srv, c: newClient(t)}
}

func newClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

type resp struct {
	status int
	body   []byte
	header http.Header
}

func (r resp) decode(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

func (e *env) do(c *http.Client, method, path string, body any, hdr ...string) resp {
	e.t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.srv.URL+BasePath+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, b, res.Header}
}

func (e *env) expect(r resp, status int) {
	e.t.Helper()
	if r.status != status {
		e.t.Fatalf("status = %d, want %d; body %s", r.status, status, r.body)
	}
}

// setup completes first-run setup and leaves e.c logged in.
func (e *env) setup() {
	e.t.Helper()
	e.expect(e.do(e.c, "POST", "/setup", SetupRequest{SetupCode: testCode, Username: "admin", Password: testPassword}), 200)
}

func TestPublicOpsMatchSpec(t *testing.T) {
	raw, err := os.ReadFile("../../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	var public []string
	for path, ops := range spec.Paths {
		for method, node := range ops {
			if method == "parameters" {
				continue
			}
			var op struct {
				Security *[]map[string][]string `yaml:"security"`
			}
			if err := node.Decode(&op); err != nil {
				t.Fatal(err)
			}
			if op.Security != nil && len(*op.Security) == 0 {
				public = append(public, strings.ToUpper(method)+" "+BasePath+path)
			}
		}
	}
	var want []string
	for k := range publicOps {
		want = append(want, k)
	}
	slices.Sort(public)
	slices.Sort(want)
	if !slices.Equal(public, want) {
		t.Fatalf("spec public ops %v != publicOps %v", public, want)
	}
}

func TestSetupFlow(t *testing.T) {
	e := newEnv(t)
	var st SetupStatus
	e.do(e.c, "GET", "/setup", nil).decode(t, &st)
	if !st.NeedsSetup {
		t.Fatal("fresh coordinator should need setup")
	}

	e.expect(e.do(e.c, "POST", "/setup", SetupRequest{SetupCode: "WRONG", Username: "admin", Password: testPassword}), 403)
	e.expect(e.do(e.c, "POST", "/setup", SetupRequest{SetupCode: testCode, Username: "admin", Password: "short"}), 400)
	bad := "ftp://x"
	e.expect(e.do(e.c, "POST", "/setup", SetupRequest{SetupCode: testCode, Username: "admin", Password: testPassword, PublicURL: &bad}), 400)

	url := "https://mesh.example.com/"
	r := e.do(e.c, "POST", "/setup", SetupRequest{SetupCode: " abcd efgh ijkl mnop ", Username: "admin", Password: testPassword, PublicURL: &url})
	e.expect(r, 200)
	cookie := r.header.Get("Set-Cookie")
	if !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Strict") {
		t.Fatalf("cookie = %q", cookie)
	}

	var me Me
	e.do(e.c, "GET", "/auth/me", nil).decode(t, &me)
	if me.Username != "admin" {
		t.Fatalf("me = %+v", me)
	}
	e.do(e.c, "GET", "/setup", nil).decode(t, &st)
	if st.NeedsSetup {
		t.Fatal("setup still needed after completion")
	}
	e.expect(e.do(newClient(t), "POST", "/setup", SetupRequest{SetupCode: testCode, Username: "evil", Password: testPassword}), 409)

	var settings Settings
	e.do(e.c, "GET", "/settings", nil).decode(t, &settings)
	if settings.PublicURL != "https://mesh.example.com" || settings.NetworkPrefix != "100.64.0.0/10" || settings.StunPort != 3478 || !settings.RelayEnabled {
		t.Fatalf("settings = %+v", settings)
	}
}

func TestAuthRequiredAndLogin(t *testing.T) {
	e := newEnv(t)
	anon := newClient(t)
	for _, p := range []string{"/nodes", "/authkeys", "/settings", "/stats", "/auth/me", "/events"} {
		e.expect(e.do(anon, "GET", p, nil), 401)
	}
	e.expect(e.do(anon, "GET", "/version", nil), 200)
	e.expect(e.do(anon, "GET", "/nope", nil), 401) // routes are not revealed

	e.setup()
	e.expect(e.do(e.c, "GET", "/nope", nil), 404)
	c := newClient(t)
	e.expect(e.do(c, "POST", "/auth/login", LoginRequest{Username: "admin", Password: "wrong password"}), 401)
	e.expect(e.do(c, "POST", "/auth/login", LoginRequest{Username: "admin", Password: testPassword}), 200)
	e.expect(e.do(c, "GET", "/nodes", nil), 200)

	e.expect(e.do(c, "POST", "/auth/logout", struct{}{}), 204)
	e.expect(e.do(c, "GET", "/nodes", nil), 401)
}

func TestCrossSiteRequestsRefused(t *testing.T) {
	e := newEnv(t)
	e.setup()

	// A form post (no JSON content type) is refused even with the cookie.
	req, _ := http.NewRequest("POST", e.srv.URL+BasePath+"/authkeys", strings.NewReader("reusable=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := e.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("form post status = %d", res.StatusCode)
	}

	body := AuthKeyCreate{Reusable: true}
	e.expect(e.do(e.c, "POST", "/authkeys", body, "Origin", "https://evil.example"), 403)
	e.expect(e.do(e.c, "POST", "/authkeys", body, "Origin", e.srv.URL), 201)
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	e.setup()
	c := newClient(t)
	limited := false
	for range 15 {
		r := e.do(c, "POST", "/auth/login", LoginRequest{Username: "admin", Password: "wrong password"})
		if r.status == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("no rate limit after 15 failed logins")
	}
}

func TestNodes(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx := context.Background()
	_, secret, _ := e.store.CreateAuthKey(ctx, store.AuthKeyOptions{Reusable: true})
	reg := func(b byte, host string) store.Node {
		n, _, err := e.store.RegisterNode(ctx, store.RegisterRequest{AuthKey: secret, WGPublicKey: [32]byte{b}, Hostname: host, OS: "linux", Prefix: netip.MustParsePrefix("100.64.0.0/10")})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	a := reg(1, "alpha")
	reg(2, "bravo")

	var nodes []Node
	e.do(e.c, "GET", "/nodes", nil).decode(t, &nodes)
	if len(nodes) != 2 || nodes[0].Name != "alpha" || nodes[0].Addresses[0] != "100.64.0.1/32" || nodes[0].Online || nodes[0].PublicKey == "" {
		t.Fatalf("nodes = %+v", nodes)
	}
	var stats Stats
	e.do(e.c, "GET", "/stats", nil).decode(t, &stats)
	if stats.Nodes != 2 || stats.Online != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	var n Node
	r := e.do(e.c, "PATCH", "/nodes/"+a.ID, NodeUpdate{Name: ptr("Web 1")})
	e.expect(r, 200)
	r.decode(t, &n)
	if n.Name != "web-1" {
		t.Fatalf("renamed = %+v", n)
	}
	e.expect(e.do(e.c, "PATCH", "/nodes/"+a.ID, NodeUpdate{Name: ptr("bravo")}), 409)
	e.expect(e.do(e.c, "PATCH", "/nodes/"+a.ID, NodeUpdate{Name: ptr(" ")}), 400)
	e.expect(e.do(e.c, "PATCH", "/nodes/"+a.ID, map[string]any{"name": "x", "extra": 1}), 400)
	e.expect(e.do(e.c, "GET", "/nodes/missing", nil), 404)

	e.expect(e.do(e.c, "DELETE", "/nodes/"+a.ID, nil), 204)
	e.expect(e.do(e.c, "DELETE", "/nodes/"+a.ID, nil), 404)
	e.do(e.c, "GET", "/nodes", nil).decode(t, &nodes)
	if len(nodes) != 1 {
		t.Fatalf("nodes after delete = %+v", nodes)
	}
}

func TestAuthKeys(t *testing.T) {
	e := newEnv(t)
	e.setup()
	desc := "laptops"
	var created AuthKeyCreated
	r := e.do(e.c, "POST", "/authkeys", AuthKeyCreate{Description: &desc, Reusable: true, TtlSeconds: 3600})
	e.expect(r, 201)
	r.decode(t, &created)
	if !strings.HasPrefix(created.Secret, store.AuthKeyPrefix) || created.Key.ExpiresAt == nil || !created.Key.Valid {
		t.Fatalf("created = %+v", created)
	}
	e.expect(e.do(e.c, "POST", "/authkeys", AuthKeyCreate{TtlSeconds: -1}), 400)
	e.expect(e.do(e.c, "POST", "/authkeys", AuthKeyCreate{TtlSeconds: 400 * 24 * 3600}), 400)

	var keys []AuthKey
	e.do(e.c, "GET", "/authkeys", nil).decode(t, &keys)
	if len(keys) != 1 || keys[0].Description != "laptops" {
		t.Fatalf("keys = %+v", keys)
	}
	if strings.Contains(string(e.do(e.c, "GET", "/authkeys", nil).body), created.Secret) {
		t.Fatal("secret returned by list")
	}

	e.expect(e.do(e.c, "DELETE", "/authkeys/"+created.Key.Id, nil), 204)
	e.do(e.c, "GET", "/authkeys", nil).decode(t, &keys)
	if !keys[0].Revoked || keys[0].Valid {
		t.Fatalf("revoked key = %+v", keys[0])
	}
	e.expect(e.do(e.c, "DELETE", "/authkeys/missing", nil), 404)
}

func TestSettingsAndPassword(t *testing.T) {
	e := newEnv(t)
	e.setup()
	e.expect(e.do(e.c, "PATCH", "/settings", SettingsUpdate{PublicURL: ptr("not a url")}), 400)
	var st Settings
	r := e.do(e.c, "PATCH", "/settings", SettingsUpdate{PublicURL: ptr("http://10.0.0.1:8080/")})
	e.expect(r, 200)
	r.decode(t, &st)
	if st.PublicURL != "http://10.0.0.1:8080" {
		t.Fatalf("settings = %+v", st)
	}
	e.expect(e.do(e.c, "PATCH", "/settings", SettingsUpdate{PublicURL: ptr("")}), 200)

	e.expect(e.do(e.c, "POST", "/auth/password", PasswordChange{CurrentPassword: "wrong password", NewPassword: "a brand new password"}), 403)
	e.expect(e.do(e.c, "POST", "/auth/password", PasswordChange{CurrentPassword: testPassword, NewPassword: "short"}), 400)
	e.expect(e.do(e.c, "POST", "/auth/password", PasswordChange{CurrentPassword: testPassword, NewPassword: "a brand new password"}), 204)
	e.expect(e.do(newClient(t), "POST", "/auth/login", LoginRequest{Username: "admin", Password: "a brand new password"}), 200)
}

func TestEventStream(t *testing.T) {
	e := newEnv(t)
	e.setup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+BasePath+"/events", http.NoBody)
	res, err := e.c.Do(req) //nolint:bodyclose // closed below; read by a goroutine
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content type = %q", res.Header.Get("Content-Type"))
	}
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(res.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
	}()
	waitLine := func(want string) {
		t.Helper()
		for {
			select {
			case l := <-lines:
				if l == want {
					return
				}
			case <-ctx.Done():
				t.Fatalf("no %q line", want)
			}
		}
	}
	waitLine("retry: 3000")
	e.ctl.Notify()
	waitLine("event: change")
}

func (e *env) api() *Server { return e.srvAPI }
