package coordinator

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func newTestServer(ui fstest.MapFS) *httptest.Server {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return httptest.NewServer(NewServer(log, ui).Handler())
}

type response struct {
	StatusCode int
	Header     http.Header
}

func get(t *testing.T, url string) (response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{StatusCode: resp.StatusCode, Header: resp.Header}, string(body)
}

var testUI = fstest.MapFS{
	"index.html":      {Data: []byte("<html>app</html>")},
	"assets/app-1.js": {Data: []byte("console.log(1)")},
	"favicon.svg":     {Data: []byte("<svg/>")},
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(testUI)
	defer srv.Close()

	resp, body := get(t, srv.URL+"/healthz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var got map[string]string
	if err := json.Unmarshal([]byte(body), &got); err != nil || got["status"] != "ok" {
		t.Fatalf("body = %q, err = %v", body, err)
	}
}

func TestVersion(t *testing.T) {
	srv := newTestServer(testUI)
	defer srv.Close()

	resp, body := get(t, srv.URL+"/api/v1/version")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"version"`) {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
}

func TestUnknownAPIIs404JSON(t *testing.T) {
	srv := newTestServer(testUI)
	defer srv.Close()

	resp, _ := get(t, srv.URL+"/api/v1/nope")
	if resp.StatusCode != http.StatusNotFound || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status = %d, content-type = %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func TestUIServing(t *testing.T) {
	srv := newTestServer(testUI)
	defer srv.Close()

	tests := []struct {
		path, wantBody, wantCache string
	}{
		{"/", "<html>app</html>", "no-cache"},
		{"/nodes/123", "<html>app</html>", "no-cache"}, // SPA fallback
		{"/assets/app-1.js", "console.log(1)", "public, max-age=31536000, immutable"},
		{"/favicon.svg", "<svg/>", "no-cache"},
	}
	for _, tt := range tests {
		resp, body := get(t, srv.URL+tt.path)
		if resp.StatusCode != http.StatusOK || body != tt.wantBody {
			t.Errorf("%s: status = %d, body = %q", tt.path, resp.StatusCode, body)
		}
		if got := resp.Header.Get("Cache-Control"); got != tt.wantCache {
			t.Errorf("%s: Cache-Control = %q, want %q", tt.path, got, tt.wantCache)
		}
	}
}

func TestUINotBuilt(t *testing.T) {
	srv := newTestServer(fstest.MapFS{".gitkeep": {}})
	defer srv.Close()

	resp, body := get(t, srv.URL+"/")
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "make web") {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
	if resp, _ := get(t, srv.URL+"/healthz"); resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
}

func TestMountedHandlersCanStream(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := NewServer(log, testUI)
	s.Mount("/stream", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flusher", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte("chunk"))
		f.Flush()
	}))
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	resp, body := get(t, srv.URL+"/stream")
	if resp.StatusCode != http.StatusOK || body != "chunk" {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
}
