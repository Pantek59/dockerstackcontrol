// Package server wires the HTTP routes: dashboard, OIDC flow endpoints,
// JSON API, health check and static assets, plus the middleware chain
// (security headers, panic recovery, request logging).
//
// The authorization policy lives here too: every stack request is checked
// server-side against the current configuration snapshot using the authz
// package — rendering choices in the GUI are cosmetic only.
package server

import (
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Pantek59/dockerstackcontrol/internal/audit"
	"github.com/Pantek59/dockerstackcontrol/internal/auth"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
	"github.com/Pantek59/dockerstackcontrol/internal/docker"
)

// Server is the fully wired application HTTP handler.
type Server struct {
	holder    *config.Holder
	runner    docker.Runner
	auth      *auth.Service
	audit     *audit.Logger
	logger    *slog.Logger
	staticFS  http.Handler
	templates map[string]*template.Template

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
}

// New wires the pieces together. logger receives request logs. An error is
// returned when the embedded templates cannot be parsed (a build-time asset,
// so this should never happen in practice).
func New(holder *config.Holder, runner docker.Runner, svc *auth.Service, aud *audit.Logger, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	templates, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	static, err := staticHandler()
	if err != nil {
		return nil, err
	}
	s := &Server{
		holder:    holder,
		runner:    runner,
		auth:      svc,
		audit:     aud,
		logger:    logger,
		templates: templates,
		staticFS:  static,
		locks:     make(map[string]*sync.Mutex),
	}

	// Inject the trusted-proxy aware client address computation into the
	// auth service so its audit lines carry the same remote_ip semantics,
	// and render HTML error pages from the embedded templates.
	svc.RemoteIP = func(r *http.Request) string { return RemoteIP(holder.Get(), r) }
	svc.RenderError = s.renderErrorPage
	return s, nil
}

// lockFor returns the per-stack mutex used to serialize actions.
func (s *Server) lockFor(name string) *sync.Mutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	mu, ok := s.locks[name]
	if !ok {
		mu = &sync.Mutex{}
		s.locks[name] = mu
	}
	return mu
}

// Handler returns the root handler with the full middleware chain.
func (s *Server) Handler() http.Handler {
	return s.withSecurityHeaders(s.withRecovery(s.withRequestLog(s.registerRoutes())))
}

func (s *Server) registerRoutes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /login", s.auth.Login)
	mux.HandleFunc("GET /auth/callback", s.auth.Callback)

	mux.Handle("POST /logout", s.auth.RequireSession(false,
		s.auth.RequireCSRF(false, http.HandlerFunc(s.auth.Logout))))
	mux.Handle("GET /{$}", s.auth.RequireSession(false, http.HandlerFunc(s.dashboard)))
	mux.Handle("GET /api/stacks", s.auth.RequireSession(true, http.HandlerFunc(s.apiStacks)))
	mux.Handle("POST /api/stacks/{name}/{action}", s.auth.RequireSession(true,
		s.auth.RequireCSRF(true, http.HandlerFunc(s.apiAction))))

	mux.Handle("GET /static/", s.staticFS)

	mux.HandleFunc("/", s.notFound)
	return mux
}

func (s *Server) healthz(rw http.ResponseWriter, r *http.Request) {
	// No Docker call: health is about the web service itself.
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("ok"))
}

// notFound handles everything the mux did not match: JSON for API paths,
// HTML otherwise. Known API paths hit with a wrong method yield 405.
func (s *Server) notFound(rw http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasPrefix(path, "/api/") {
		switch {
		case path == "/api/stacks" && r.Method != http.MethodGet:
			rw.Header().Set("Allow", "GET")
			writeJSONError(rw, http.StatusMethodNotAllowed, "method not allowed")
			return
		case strings.HasPrefix(path, "/api/stacks/") && r.Method != http.MethodPost:
			rw.Header().Set("Allow", "POST")
			writeJSONError(rw, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeJSONError(rw, http.StatusNotFound, "not found")
		return
	}
	s.renderErrorPage(rw, r, http.StatusNotFound, "page not found")
}

func isAPIPath(p string) bool { return strings.HasPrefix(p, "/api/") }

// withSecurityHeaders applies the strict default headers to every response.
func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		h := rw.Header()
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(rw, r)
	})
}

// withRecovery turns handler panics into 500 responses instead of dropped
// connections, without leaking stack traces to clients.
func (s *Server) withRecovery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic recovered",
					"method", r.Method, "path", r.URL.Path, "panic", rec)
				if isAPIPath(r.URL.Path) {
					writeJSONError(rw, http.StatusInternalServerError, "internal error")
				} else {
					s.renderErrorPage(rw, r, http.StatusInternalServerError, "internal error")
				}
			}
		}()
		next.ServeHTTP(rw, r)
	})
}

// withRequestLog emits one structured line per request.
func (s *Server) withRequestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: rw, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.logger.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_ip", RemoteIP(s.holder.Get(), r),
		)
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

// Unwrap lets middleware chains and net/http internals reach the original
// ResponseWriter (needed for Flusher/Sniffer support).
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// RemoteIP returns the client address for logging and audit entries.
//
// If X-Forwarded-For is present and the direct peer matches one of the
// configured trusted proxy CIDRs, the first forwarded address is the client
// address; otherwise the direct peer address is used (never a header, which
// would be trivially spoofable).
func RemoteIP(cfg *config.Config, r *http.Request) string {
	peer := peerIP(r)
	if peer == nil {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return host
		}
		return r.RemoteAddr
	}
	if len(cfg.Server.TrustedProxyNets) > 0 {
		for _, n := range cfg.Server.TrustedProxyNets {
			if n.Contains(peer) {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					first := strings.TrimSpace(strings.Split(xff, ",")[0])
					if ip := net.ParseIP(first); ip != nil {
						return ip.String()
					}
				}
				break
			}
		}
	}
	return peer.String()
}

func peerIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return net.ParseIP(r.RemoteAddr)
	}
	return net.ParseIP(host)
}
