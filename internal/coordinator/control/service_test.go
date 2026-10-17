package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/sneakybugmaster/transporter/internal/coordinator/store"
	controlv1 "github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1"
	"github.com/sneakybugmaster/transporter/internal/proto/transporter/control/v1/controlv1connect"
)

type env struct {
	store   *store.Store
	svc     *Service
	client  controlv1connect.ControlServiceClient
	authKey string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.OpenMemory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	_, secret, err := st.CreateAuthKey(ctx, store.AuthKeyOptions{Reusable: true})
	if err != nil {
		t.Fatal(err)
	}

	svc := NewService(st, netip.MustParsePrefix("100.64.0.0/10"), Options{STUNPort: 3478, RelayEnabled: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	mux.Handle(svc.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &env{
		store:   st,
		svc:     svc,
		client:  controlv1connect.NewControlServiceClient(srv.Client(), srv.URL),
		authKey: secret,
	}
}

func key(b byte) []byte {
	k := make([]byte, 32)
	k[0] = b
	return k
}

func (e *env) register(t *testing.T, b byte, hostname string) (*controlv1.Node, string) {
	t.Helper()
	resp, err := e.client.Register(context.Background(), connect.NewRequest(&controlv1.RegisterRequest{
		AuthKey: e.authKey, WireguardPublicKey: key(b), Hostname: hostname, Os: "linux",
	}))
	if err != nil {
		t.Fatalf("register %s: %v", hostname, err)
	}
	return resp.Msg.GetNode(), resp.Msg.GetNodeToken()
}

type watch struct {
	cancel context.CancelFunc
	ch     chan *controlv1.WatchNetmapResponse
	errc   chan error
}

func (e *env) watch(t *testing.T, token string, endpoints ...string) *watch {
	t.Helper()
	return e.watchReq(t, token, &controlv1.WatchNetmapRequest{Endpoints: endpoints})
}

func (e *env) watchReq(t *testing.T, token string, msg *controlv1.WatchNetmapRequest) *watch {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req := connect.NewRequest(msg)
	req.Header().Set("Authorization", "Bearer "+token)
	stream, err := e.client.WatchNetmap(ctx, req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	w := &watch{cancel: cancel, ch: make(chan *controlv1.WatchNetmapResponse, 16), errc: make(chan error, 1)}
	go func() {
		defer stream.Close()
		for stream.Receive() {
			w.ch <- stream.Msg()
		}
		w.errc <- stream.Err()
	}()
	t.Cleanup(cancel)
	return w
}

// next waits for a netmap satisfying cond.
func (w *watch) next(t *testing.T, cond func(*controlv1.WatchNetmapResponse) bool) *controlv1.WatchNetmapResponse {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case nm := <-w.ch:
			if cond(nm) {
				return nm
			}
		case err := <-w.errc:
			t.Fatalf("stream ended: %v", err)
		case <-timeout:
			t.Fatal("timed out waiting for netmap")
		}
	}
}

func peerNamed(nm *controlv1.WatchNetmapResponse, name string) *controlv1.Node {
	for _, p := range nm.GetPeers() {
		if p.GetName() == name {
			return p
		}
	}
	return nil
}

func TestRegisterValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	_, err := e.client.Register(ctx, connect.NewRequest(&controlv1.RegisterRequest{AuthKey: e.authKey, WireguardPublicKey: []byte{1, 2}}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("short key: err = %v", err)
	}
	_, err = e.client.Register(ctx, connect.NewRequest(&controlv1.RegisterRequest{AuthKey: "trk_nope", WireguardPublicKey: key(1)}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("bad auth key: err = %v", err)
	}

	node, token := e.register(t, 1, "alpha")
	if node.GetName() != "alpha" || !slices.Equal(node.GetAddresses(), []string{"100.64.0.1/32"}) || token == "" {
		t.Fatalf("node = %v, token = %q", node, token)
	}
}

func TestWatchNetmapRequiresToken(t *testing.T) {
	e := newEnv(t)
	for _, tok := range []string{"", "trn_bogus"} {
		req := connect.NewRequest(&controlv1.WatchNetmapRequest{})
		if tok != "" {
			req.Header().Set("Authorization", "Bearer "+tok)
		}
		stream, err := e.client.WatchNetmap(context.Background(), req)
		if err == nil {
			for stream.Receive() {
				t.Fatal("unexpected message")
			}
			err = stream.Err()
		}
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("token %q: err = %v", tok, err)
		}
	}
}

func TestWatchNetmapRejectsBadEndpoints(t *testing.T) {
	e := newEnv(t)
	_, token := e.register(t, 1, "alpha")
	req := connect.NewRequest(&controlv1.WatchNetmapRequest{Endpoints: []string{"not-an-endpoint"}})
	req.Header().Set("Authorization", "Bearer "+token)
	stream, err := e.client.WatchNetmap(context.Background(), req)
	if err == nil {
		for stream.Receive() {
		}
		err = stream.Err()
	}
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("err = %v", err)
	}
}

func TestNetmapUpdates(t *testing.T) {
	e := newEnv(t)
	_, tokA := e.register(t, 1, "alpha")
	wa := e.watch(t, tokA, "192.0.2.10:41641")

	nm := wa.next(t, func(*controlv1.WatchNetmapResponse) bool { return true })
	if nm.GetSelf().GetName() != "alpha" || len(nm.GetPeers()) != 0 || nm.GetNetworkPrefix() != "100.64.0.0/10" ||
		nm.GetStunPort() != 3478 || !nm.GetRelayEnabled() {
		t.Fatalf("initial netmap = %v", nm)
	}
	if !nm.GetSelf().GetOnline() {
		t.Fatal("self should be online while watching")
	}

	// A new node registers: alpha learns about it (offline, no endpoints yet).
	_, tokB := e.register(t, 2, "bravo")
	nm = wa.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return peerNamed(nm, "bravo") != nil })
	if b := peerNamed(nm, "bravo"); b.GetOnline() || !slices.Equal(b.GetAddresses(), []string{"100.64.0.2/32"}) {
		t.Fatalf("bravo = %v", b)
	}

	// Bravo connects: alpha sees it online with its endpoints.
	wb := e.watch(t, tokB, "198.51.100.7:41641")
	nm = wa.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return peerNamed(nm, "bravo").GetOnline() })
	if eps := peerNamed(nm, "bravo").GetEndpoints(); !slices.Contains(eps, "198.51.100.7:41641") {
		t.Fatalf("bravo endpoints = %v", eps)
	}
	nmB := wb.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return peerNamed(nm, "alpha").GetOnline() })
	if !slices.Equal(peerNamed(nmB, "alpha").GetWireguardPublicKey(), key(1)) {
		t.Fatal("bravo got wrong key for alpha")
	}

	// Bravo disconnects: alpha sees it go offline.
	wb.cancel()
	wa.next(t, func(nm *controlv1.WatchNetmapResponse) bool {
		b := peerNamed(nm, "bravo")
		return b != nil && !b.GetOnline()
	})

	// Bravo is deleted: it disappears from alpha's netmap.
	bravo, err := e.store.NodeByName(context.Background(), "bravo")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.DeleteNode(context.Background(), bravo.ID); err != nil {
		t.Fatal(err)
	}
	e.svc.Notify()
	wa.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return peerNamed(nm, "bravo") == nil })
}

func TestDeletedNodeStreamEnds(t *testing.T) {
	e := newEnv(t)
	node, tok := e.register(t, 1, "alpha")
	w := e.watch(t, tok, "192.0.2.10:41641")
	w.next(t, func(*controlv1.WatchNetmapResponse) bool { return true })

	if err := e.store.DeleteNode(context.Background(), node.GetId()); err != nil {
		t.Fatal(err)
	}
	e.svc.Notify()
	select {
	case err := <-w.errc:
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end")
	}
}

func TestHeartbeatResends(t *testing.T) {
	e := newEnv(t)
	e.svc.heartbeat = 50 * time.Millisecond
	_, tok := e.register(t, 1, "alpha")
	w := e.watch(t, tok, "192.0.2.10:41641")
	for range 3 {
		w.next(t, func(*controlv1.WatchNetmapResponse) bool { return true })
	}
}

func TestParseEndpoints(t *testing.T) {
	if _, err := parseEndpoints([]string{"0.0.0.0:1"}); err == nil {
		t.Error("unspecified address accepted")
	}
	if _, err := parseEndpoints([]string{"10.0.0.1:0"}); err == nil {
		t.Error("port 0 accepted")
	}
	got, err := parseEndpoints([]string{"10.0.0.1:1", "[2001:db8::1]:2", "10.0.0.1:1"})
	if err != nil || !slices.Equal(got, []string{"10.0.0.1:1", "[2001:db8::1]:2"}) {
		t.Errorf("got %v, %v", got, err)
	}
	many := make([]string, maxEndpoints+1)
	for i := range many {
		many[i] = "10.0.0.1:1"
	}
	if _, err := parseEndpoints(many); err == nil {
		t.Error("too many endpoints accepted")
	}
}

func TestUpdateEndpoints(t *testing.T) {
	e := newEnv(t)
	_, tokA := e.register(t, 1, "alpha")
	_, tokB := e.register(t, 2, "bravo")
	wa := e.watch(t, tokA, "192.0.2.10:41641")
	e.watch(t, tokB, "198.51.100.7:41641")
	wa.next(t, func(nm *controlv1.WatchNetmapResponse) bool { return peerNamed(nm, "bravo").GetOnline() })

	update := func(token string, eps ...string) error {
		req := connect.NewRequest(&controlv1.UpdateEndpointsRequest{Endpoints: eps})
		if token != "" {
			req.Header().Set("Authorization", "Bearer "+token)
		}
		_, err := e.client.UpdateEndpoints(context.Background(), req)
		return err
	}
	if err := update(tokB, "198.51.100.7:41641", "203.0.113.50:61000"); err != nil {
		t.Fatal(err)
	}
	wa.next(t, func(nm *controlv1.WatchNetmapResponse) bool {
		return slices.Contains(peerNamed(nm, "bravo").GetEndpoints(), "203.0.113.50:61000")
	})

	if err := update("", "198.51.100.7:41641"); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("no token: err = %v", err)
	}
	if err := update(tokB, "bogus"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("bad endpoint: err = %v", err)
	}
}
