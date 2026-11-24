// Package auth implements the OIDC login flow (authorization code flow with
// PKCE), stateless signed/encrypted session cookies, and CSRF protection.
//
// Sessions carry username, group memberships, a per-session CSRF token and an
// expiry; they are stored only in the client (securecookie), so no server
// side session store exists. The OIDC provider is rebuilt whenever the
// configuration is reloaded; sessions stay valid as long as the session keys
// are unchanged.
package auth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"

	"github.com/Pantek59/dockerstackcontrol/internal/audit"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
)

// Cookie and form/header names, exported for tests and the server package.
const (
	SessionCookieName = "stackctl_session"
	FlowCookieName    = "stackctl_flow"
	// FlowCookieTTL bounds the login flow (state/nonce/PKCE verifier).
	FlowCookieTTL = 10 * time.Minute
	// CSRFHeader is the custom header carrying the CSRF token on API calls.
	CSRFHeader = "X-CSRF-Token"
	// CSRFFormField is the fallback for HTML form posts (e.g. logout).
	CSRFFormField = "csrf_token"
)

// Session is the stateless, encrypted-and-signed payload of the session
// cookie. Nothing sensitive is stored: no tokens, no client secret.
type Session struct {
	Username  string    `json:"username"`
	Groups    []string  `json:"groups"`
	CSRFToken string    `json:"csrf_token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the session has exceeded its wall-clock expiry.
func (s Session) Expired(now time.Time) bool { return now.After(s.ExpiresAt) }

// flowState is the short-lived payload of the login flow cookie.
type flowState struct {
	State     string    `json:"state"`
	Nonce     string    `json:"nonce"`
	Verifier  string    `json:"verifier"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Service owns OIDC bootstrap, cookie codecs and the auth handlers.
type Service struct {
	Holder *config.Holder
	Audit  *audit.Logger

	// RemoteIP computes the client address for audit entries. server
	// injects the trusted-proxy-aware implementation; nil falls back to the
	// direct peer address.
	RemoteIP func(r *http.Request) string

	// RenderError renders an HTML error page. server injects it; nil falls
	// back to a plain-text response.
	RenderError func(rw http.ResponseWriter, r *http.Request, status int, msg string)

	mu        sync.RWMutex
	provider  *oidc.Provider
	oauth2cfg *oauth2.Config
	verifier  *oidc.IDTokenVerifier
	session   *securecookie.SecureCookie
	flow      *securecookie.SecureCookie
}

// NewService performs OIDC discovery against the configured issuer and
// registers a reload hook so a configuration change rebuilds (or keeps) the
// provider. Discovery failure aborts startup: without a reachable identity
// provider login cannot work.
func NewService(holder *config.Holder, aud *audit.Logger) (*Service, error) {
	s := &Service{Holder: holder, Audit: aud}
	if err := s.rebuild(holder.Get()); err != nil {
		return nil, err
	}
	holder.OnChange(func(c *config.Config) error {
		if err := s.rebuild(c); err != nil {
			// Keep the previous provider; report the failure upward.
			return err
		}
		return nil
	})
	return s, nil
}

// rebuild discovers the provider and (re)creates codecs from cfg. It mutates
// state only when everything succeeded, so a failed reload keeps the current
// setup.
func (s *Service) rebuild(cfg *config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, cfg.OIDC.Issuer)
	if err != nil {
		return err
	}

	endpoint := provider.Endpoint()
	redirectURL := redirectURI(cfg)
	oauth2cfg := &oauth2.Config{
		ClientID:     cfg.OIDC.ClientID,
		ClientSecret: cfg.OIDC.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  redirectURL,
		Scopes:       cfg.OIDC.Scopes,
	}

	sessionCodec, flowCodec := newCodecs(cfg)

	s.mu.Lock()
	s.provider = provider
	s.oauth2cfg = oauth2cfg
	s.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.OIDC.ClientID})
	s.session = sessionCodec
	s.flow = flowCodec
	s.mu.Unlock()
	return nil
}

func redirectURI(cfg *config.Config) string {
	u, err := url.Parse(cfg.Server.ExternalURL)
	if err != nil {
		return cfg.Server.ExternalURL + "/auth/callback"
	}
	u.Path = path.Join(u.Path, "auth", "callback")
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

// newCodecs builds the session and flow cookie codecs from cfg.
func newCodecs(cfg *config.Config) (session, flow *securecookie.SecureCookie) {
	session = securecookie.New(cfg.Server.HashKey, cfg.Server.BlockKey)
	session.SetSerializer(securecookie.JSONEncoder{})
	session.MaxAge(int(cfg.Server.SessionTTL.Std().Seconds()))

	flow = securecookie.New(cfg.Server.HashKey, cfg.Server.BlockKey)
	flow.SetSerializer(securecookie.JSONEncoder{})
	flow.MaxAge(int(FlowCookieTTL.Seconds()))
	return session, flow
}

// NewSessionService builds a Service without OIDC discovery: only the session
// cookie and CSRF functionality is wired (session codecs from cfg). Login and
// Callback require the full NewService. Intended for tests of consumers of the
// session middleware (e.g. the server package) that do not exercise the login
// flow.
func NewSessionService(holder *config.Holder, aud *audit.Logger) (*Service, error) {
	cfg := holder.Get()
	if cfg.Server.HashKey == nil || cfg.Server.BlockKey == nil {
		return nil, errors.New("auth: session keys are not decoded; run config.Validate first")
	}
	s := &Service{Holder: holder, Audit: aud}
	session, flow := newCodecs(cfg)
	s.mu.Lock()
	s.session = session
	s.flow = flow
	s.mu.Unlock()
	return s, nil
}

func (s *Service) snapshot() (oauth2Cfg *oauth2.Config, verifier *oidc.IDTokenVerifier, session, flow *securecookie.SecureCookie) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oauth2cfg, s.verifier, s.session, s.flow
}
