// Package coordinator implements the public control server: admin API,
// configuration UI and (in later phases) the control plane, STUN and relay.
package coordinator

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"
)

// Server is the coordinator's HTTP front end.
type Server struct {
	log    *slog.Logger
	ui     fs.FS
	mounts []mount
}

type mount struct {
	pattern string
	handler http.Handler
}

// NewServer returns a Server that serves the given UI filesystem at "/".
func NewServer(log *slog.Logger, ui fs.FS) *Server {
	return &Server{log: log, ui: ui}
}

// Mount registers an additional handler, such as the control-plane service.
// It must be called before Handler.
func (s *Server) Mount(pattern string, h http.Handler) {
	s.mounts = append(s.mounts, mount{pattern, h})
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	for _, m := range s.mounts {
		mux.Handle(m.pattern, m.handler)
	}
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	})
	mux.Handle("/", s.uiHandler())
	return s.logRequests(mux)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// uiHandler serves the single-page app. Unknown paths fall back to
// index.html so client-side routing works; hashed assets are cached forever.
func (s *Server) uiHandler() http.Handler {
	if _, err := fs.Stat(s.ui, "index.html"); err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("Transporter coordinator is running, but the web UI was not built into this binary.\nRun `make web` and rebuild.\n"))
		})
	}
	files := http.FileServerFS(s.ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if _, err := fs.Stat(s.ui, name); errors.Is(err, fs.ErrNotExist) {
			// SPA fallback: let the client router handle the path.
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/"
			name = "index.html"
			r = r2
		}
		if strings.HasPrefix(name, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Flush supports streaming responses (control-plane streams need it).
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" {
			return // polled every few seconds by health checks
		}
		s.log.Debug("http request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration", time.Since(start))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
