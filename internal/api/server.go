package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/aardsoft/tinydns-sidecar/internal/config"
	"github.com/aardsoft/tinydns-sidecar/internal/storage"
)

// Server holds shared dependencies for all HTTP handlers.
type Server struct {
	cfg   *config.Config
	store storage.Store
}

// NewServer creates a Server with the given configuration and store.
func NewServer(cfg *config.Config, store storage.Store) *Server {
	return &Server{cfg: cfg, store: store}
}

// Handler builds and returns the root HTTP handler with all routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	yamlTypes := []string{"application/yaml", "application/x-yaml", "text/yaml"}

	// Server-level format gates — checked before auth so the denial is cheap.
	// formatGate("yaml") blocks when server.format == "raw", and vice-versa.
	yamlGate := s.formatGate("yaml")
	rawGate := s.formatGate("raw")

	// Zone routes — authenticated per-zone, YAML bodies.
	zoneMW := s.zoneAuthMiddleware
	yamlMW := requireContentType(yamlTypes...)

	mux.Handle("PUT /zones/{zone}", yamlGate(zoneMW(yamlMW(http.HandlerFunc(s.handlePutZone)))))
	mux.Handle("PATCH /zones/{zone}", yamlGate(zoneMW(yamlMW(http.HandlerFunc(s.handlePatchZone)))))
	mux.Handle("GET /zones/{zone}", yamlGate(zoneMW(http.HandlerFunc(s.handleGetZone))))
	mux.Handle("DELETE /zones/{zone}", yamlGate(zoneMW(http.HandlerFunc(s.handleDeleteZone))))

	// Raw data routes — authenticated per-key, plain text bodies.
	dataMW := s.dataAuthMiddleware
	plainMW := requireContentType("text/plain")

	mux.Handle("POST /data", rawGate(dataMW(plainMW(http.HandlerFunc(s.handlePostData)))))
	mux.Handle("GET /data", rawGate(dataMW(http.HandlerFunc(s.handleGetData))))
	mux.Handle("DELETE /data", rawGate(dataMW(http.HandlerFunc(s.handleDeleteData))))

	// Capabilities — authenticated, no body, returns key permissions and format.
	// Not gated: always reachable so clients can discover the server's format.
	mux.Handle("GET /capabilities", dataMW(http.HandlerFunc(s.handleGetCapabilities)))

	return loggingMiddleware(mux)
}

// formatGate returns a middleware that rejects requests when the server-wide
// format setting prohibits the given route family.
// routeFormat is "yaml" (for /zones routes) or "raw" (for /data routes).
// The gate is a no-op when server.format is empty (unrestricted default).
func (s *Server) formatGate(routeFormat string) func(http.Handler) http.Handler {
	serverFormat := s.cfg.Server.Format
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if serverFormat != "" && serverFormat != routeFormat {
				writeError(w, http.StatusForbidden,
					"server is configured for "+serverFormat+"-only mode; "+routeFormat+" operations are not permitted")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// loggingMiddleware logs each request with method, path, status, and duration.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// statusRecorder wraps ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// ListenAndServe starts the HTTP(S) server on the configured address.
func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:         s.cfg.Server.Listen,
		Handler:      http.MaxBytesHandler(s.Handler(), 1<<20), // 1 MB body limit
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	tlsCfg := s.cfg.Server.TLS
	if tlsCfg.Cert != "" && tlsCfg.Key != "" {
		slog.Info("starting HTTPS server", "addr", s.cfg.Server.Listen)
		return srv.ListenAndServeTLS(tlsCfg.Cert, tlsCfg.Key)
	}

	slog.Info("starting HTTP server", "addr", s.cfg.Server.Listen)
	return srv.ListenAndServe()
}
