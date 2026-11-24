package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Pantek59/dockerstackcontrol/internal/config"
)

// Sentinel errors surfaced by session decoding.
var (
	errNoSession = errors.New("no session")
	errExpired   = errors.New("session expired")
)

type ctxKey int

const userCtxKey ctxKey = 1

// User is the authenticated identity attached to a request by RequireSession.
type User struct {
	Username  string
	Groups    []string
	CSRFToken string
}

// UserFrom returns the request's authenticated user, if any.
func UserFrom(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userCtxKey).(User)
	return u, ok
}

// remoteIP falls back to the direct peer when no RemoteIP function was
// injected (intended for tests).
func (s *Service) remoteIP(r *http.Request) string {
	if s.RemoteIP != nil {
		return s.RemoteIP(r)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// renderError uses the injected template renderer or plain text.
func (s *Service) renderError(rw http.ResponseWriter, r *http.Request, status int, msg string) {
	if s.RenderError != nil {
		s.RenderError(rw, r, status, msg)
		return
	}
	http.Error(rw, msg, status)
}

// DecodeSession parses and validates a session cookie value. Exported for
// tests and diagnostics.
func (s *Service) DecodeSession(value string) (Session, error) {
	_, _, codec, _ := s.snapshot()
	var sess Session
	if err := codec.Decode(SessionCookieName, value, &sess); err != nil {
		return Session{}, err
	}
	return sess, nil
}

// EncodeSession produces a session cookie value. Exported for tests.
func (s *Service) EncodeSession(sess Session) (string, error) {
	_, _, codec, _ := s.snapshot()
	return codec.Encode(SessionCookieName, sess)
}

// sessionCookie builds the session cookie with all hardening flags set.
func (s *Service) sessionCookie(cfg *config.Config, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   cfg.Server.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

// decodeSessionCookie reads the session from the request (or empty when
// absent/invalid/expired).
func (s *Service) decodeSessionCookie(r *http.Request) (Session, error) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return Session{}, errNoSession
	}
	sess, err := s.DecodeSession(c.Value)
	if err != nil {
		return Session{}, err
	}
	if sess.Expired(time.Now()) {
		return Session{}, errExpired
	}
	return sess, nil
}

// RequireSession resolves the session cookie and puts the user in the request
// context. With api=true a missing session yields a 401 JSON body; with
// api=false it redirects to /login. An expired session is cleared.
func (s *Service) RequireSession(api bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		cfg := s.Holder.Get()
		sess, err := s.decodeSessionCookie(r)
		if err != nil {
			if err == errExpired || err == errNoSession {
				// Expired tokens are cleared; anything else (corrupt cookie)
				// is treated like no session at all.
				if err == errExpired {
					http.SetCookie(rw, s.sessionCookie(cfg, "", -1))
				}
				if api {
					writeJSONError(rw, http.StatusUnauthorized, err.Error())
				} else {
					http.Redirect(rw, r, "/login", http.StatusFound)
				}
				return
			}
			if api {
				writeJSONError(rw, http.StatusUnauthorized, "no session")
			} else {
				http.Redirect(rw, r, "/login", http.StatusFound)
			}
			return
		}
		user := User{Username: sess.Username, Groups: sess.Groups, CSRFToken: sess.CSRFToken}
		next.ServeHTTP(rw, r.WithContext(context.WithValue(r.Context(), userCtxKey, user)))
	})
}

// writeJSONError writes a small JSON error body for API responses.
func writeJSONError(rw http.ResponseWriter, status int, msg string) {
	body, err := json.Marshal(map[string]string{"error": msg})
	if err != nil { // unreachable for these inputs
		body = []byte(`{"error":"internal error"}`)
	}
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	_, _ = rw.Write(body)
}

// RequireCSRF checks the Origin header and the CSRF token for every POST.
// Order matters: this middleware must run after RequireSession, because the
// session carries the expected token.
//
//   - If an Origin header is present, its scheme and host must equal the
//     configured external URL's. A missing Origin is tolerated (non-browser
//     clients); the token check still applies.
//   - The token comes from the X-CSRF-Token header, or, for classic form
//     posts (logout), from the csrf_token form field.
//
// Any mismatch is a 403 before the handler (and any Docker call) runs.
func (s *Service) RequireCSRF(api bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		cfg := s.Holder.Get()
		user, ok := UserFrom(r.Context())
		if !ok {
			// Middleware misuse: session check did not run.
			if api {
				writeJSONError(rw, http.StatusUnauthorized, "no session")
			} else {
				s.renderError(rw, r, http.StatusUnauthorized, "authentication required")
			}
			return
		}

		if !originMatches(cfg.Server.ExternalURL, r) {
			s.Audit.Denied(user.Username, r.URL.Path, s.remoteIP(r), "origin not allowed")
			if api {
				writeJSONError(rw, http.StatusForbidden, "origin not allowed")
			} else {
				s.renderError(rw, r, http.StatusForbidden, "origin not allowed")
			}
			return
		}

		token := r.Header.Get(CSRFHeader)
		if token == "" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			if err := r.ParseForm(); err == nil {
				token = r.PostFormValue(CSRFFormField)
			}
		}

		given := []byte(token)
		want := []byte(user.CSRFToken)
		if len(want) == 0 || len(given) != len(want) || subtle.ConstantTimeCompare(given, want) != 1 {
			s.Audit.Denied(user.Username, r.URL.Path, s.remoteIP(r), "invalid CSRF token")
			if api {
				writeJSONError(rw, http.StatusForbidden, "invalid CSRF token")
			} else {
				s.renderError(rw, r, http.StatusForbidden, "invalid CSRF token")
			}
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// originMatches compares the Origin header against the external URL's
// scheme and host (authority), ignoring case as URLs require.
func originMatches(externalURL string, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	ext, err := url.Parse(externalURL)
	if err != nil || ext.Scheme == "" || ext.Host == "" {
		return false
	}
	o, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(o.Scheme, ext.Scheme) && strings.EqualFold(o.Host, ext.Host)
}
