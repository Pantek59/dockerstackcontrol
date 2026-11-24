package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/oauth2-proxy/mockoidc"

	"github.com/Pantek59/dockerstackcontrol/internal/audit"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
)

// harness wires a full stackctl auth service against a running mock OIDC
// provider and starts it on a loopback port.
type harness struct {
	srv  *httptest.Server
	mock *mockoidc.MockOIDC
	svc  *Service
	cfg  *config.Config
}

func newHarness(t *testing.T, mutate func(c *config.Config)) *harness {
	t.Helper()

	m, err := mockoidc.Run() // listens on 127.0.0.1 with a random port
	if err != nil {
		t.Fatalf("mockoidc.Run() error = %v", err)
	}
	t.Cleanup(func() { _ = m.Shutdown() })

	cfg := &config.Config{
		Server: config.Server{
			Listen:          "127.0.0.1:0",
			ExternalURL:     "http://localhost", // replaced with the real server URL below
			CookieSecure:    false,
			SessionTTL:      config.Duration(time.Hour),
			SessionHashKey:  base64.StdEncoding.EncodeToString(keyBytes(t, 64)),
			SessionBlockKey: base64.StdEncoding.EncodeToString(keyBytes(t, 32)),
			CommandTimeout:  config.Duration(30 * time.Second),
		},
		OIDC: config.OIDC{
			Issuer:        m.Issuer(),
			ClientID:      m.ClientID,
			ClientSecret:  m.ClientSecret,
			Scopes:        []string{"openid", "profile", "email", "groups"},
			UsernameClaim: "preferred_username",
			GroupsClaim:   "groups",
		},
		Docker: config.Docker{ComposeBinary: "docker"},
	}
	if mutate != nil {
		mutate(cfg)
	}

	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	srv.Start()
	t.Cleanup(srv.Close)

	cfg.Server.ExternalURL = srv.URL // the redirect URI must point at the test server
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}

	// The flow auto-approves with a queued user; queue alice for all tests.
	m.QueueUser(&mockoidc.MockUser{
		Subject:           "alice-sub",
		Email:             "alice@example.com",
		EmailVerified:     true,
		PreferredUsername: "alice",
		Groups:            []string{"stackctl-users", "admins"},
	})

	holder := config.NewStaticHolder(cfg)
	aud := audit.New(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	svc, err := NewService(holder, aud)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	mux.HandleFunc("GET /login", svc.Login)
	mux.HandleFunc("GET /auth/callback", svc.Callback)
	mux.HandleFunc("POST /logout", func(w http.ResponseWriter, r *http.Request) {
		svc.RequireSession(false, svc.RequireCSRF(false, http.HandlerFunc(svc.Logout))).ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /protected", func(w http.ResponseWriter, r *http.Request) {
		svc.RequireSession(false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := UserFrom(r.Context())
			if !ok {
				t.Error("protected handler without user in context")
				return
			}
			_, _ = w.Write([]byte("user=" + u.Username + " csrf=" + u.CSRFToken))
		})).ServeHTTP(w, r)
	})

	return &harness{srv: srv, mock: m, svc: svc, cfg: cfg}
}

// keyBytes returns n deterministic, distinct bytes; securecookie only needs
// consistent keys across the test.
func keyBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// noRedirectClient returns an http.Client that does not follow redirects.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// loginFull performs the complete authorization code flow with PKCE against
// the mock provider. It returns the final callback response and the session
// cookie value.
func loginFull(t *testing.T, h *harness) (*http.Response, string) {
	t.Helper()
	client := noRedirectClient()
	cookies := map[string]string{}

	get := func(u string) *http.Response {
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			t.Fatal(err)
		}
		for name, value := range cookies {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", u, err)
		}
		for _, c := range resp.Cookies() {
			if c.Name == FlowCookieName || c.Name == SessionCookieName {
				cookies[c.Name] = c.Value
			}
		}
		return resp
	}

	// 1. Start the flow at /login.
	resp := get(h.srv.URL + "/login")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/login: status = %d, want 302", resp.StatusCode)
	}
	authURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("/login location: %v", err)
	}
	if authURL.Query().Get("code_challenge") == "" || authURL.Query().Get("code_challenge_method") != "S256" {
		t.Error("/login did not include PKCE S256 parameters")
	}

	// 2. The mock provider authorizes (auto-approve) and redirects back.
	resp = get(authURL.String())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status = %d, want 302", resp.StatusCode)
	}
	callbackURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("authorize location: %v", err)
	}

	// 3. The stackctl callback exchanges the code and sets the session.
	resp = get(callbackURL.String())
	return resp, cookies[SessionCookieName]
}

func TestFullLoginFlow(t *testing.T) {
	h := newHarness(t, nil)
	resp, sessionValue := loginFull(t, h)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback: status = %d, location = %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if sessionValue == "" {
		t.Fatal("callback did not set a session cookie")
	}

	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionValue})
	rec := httptest.NewRecorder()
	h.srv.Config.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("protected: status = %d", rec.Code)
	}
	if body := rec.Body.String(); !strings.HasPrefix(body, "user=alice csrf=") {
		t.Errorf("protected body = %q, want the user identity", body)
	}

	sess, err := h.svc.DecodeSession(sessionValue)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Username != "alice" {
		t.Errorf("username = %q, want alice", sess.Username)
	}
	if len(sess.Groups) == 0 {
		t.Error("groups claim missing from session")
	}
	if sess.CSRFToken == "" {
		t.Error("session has no CSRF token")
	}
	if time.Until(sess.ExpiresAt) < 50*time.Minute {
		t.Errorf("session expires in %v, want ~1h", time.Until(sess.ExpiresAt))
	}
}

func TestLoginWithRequiredGroupAllowsMember(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.OIDC.RequiredGroup = "stackctl-users" })
	resp, value := loginFull(t, h)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("allowed member: status = %d, want 302", resp.StatusCode)
	}
	if value == "" {
		t.Error("allowed member got no session cookie")
	}
}

func TestLoginWithRequiredGroupDeniesNonMember(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.OIDC.RequiredGroup = "not-a-member-group" })
	resp, value := loginFull(t, h)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denied non-member: status = %d, want 403", resp.StatusCode)
	}
	if value != "" {
		t.Error("denied non-member must not receive a session cookie")
	}
}

func TestCallbackInvalidState(t *testing.T) {
	h := newHarness(t, nil)
	client := noRedirectClient()

	resp, err := client.Get(h.srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	var flow *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == FlowCookieName {
			flow = c
		}
	}

	// The provider authorizes, but we present a tampered state.
	resp2, err := client.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := url.Parse(resp2.Header.Get("Location"))
	q := cb.Query()
	q.Set("state", "tampered-state")
	cb.RawQuery = q.Encode()
	req, _ := http.NewRequest("GET", cb.String(), nil)
	req.AddCookie(flow)
	resp3, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("callback with invalid state: status = %d, want 400", resp3.StatusCode)
	}
	for _, c := range resp3.Cookies() {
		if c.Name == SessionCookieName {
			t.Error("invalid state must not create a session cookie")
		}
	}
}

func TestCallbackInvalidNonce(t *testing.T) {
	h := newHarness(t, nil)
	client := noRedirectClient()

	resp, err := client.Get(h.srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	var flow *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == FlowCookieName {
			flow = c
		}
	}

	// Request a token with a different nonce: the ID token carries the wrong
	// nonce while state and the flow cookie stay valid.
	authURL, _ := url.Parse(resp.Header.Get("Location"))
	q := authURL.Query()
	q.Set("nonce", "evil-nonce")
	authURL.RawQuery = q.Encode()
	resp2, err := client.Get(authURL.String())
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := url.Parse(resp2.Header.Get("Location"))
	req, _ := http.NewRequest("GET", cb.String(), nil)
	req.AddCookie(flow)
	resp3, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp3.StatusCode != http.StatusBadRequest {
		t.Errorf("callback with invalid nonce: status = %d, want 400", resp3.StatusCode)
	}
}

func TestCallbackWithoutFlowCookie(t *testing.T) {
	h := newHarness(t, nil)
	client := noRedirectClient()
	resp, err := client.Get(h.srv.URL + "/auth/callback?state=x&code=y")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	h := newHarness(t, nil)
	past := Session{
		Username:  "alice",
		Groups:    []string{"admins"},
		CSRFToken: "csrf",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	value, err := h.svc.EncodeSession(past)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: value})

	rec := httptest.NewRecorder()
	h.svc.RequireSession(false, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("expired session must not reach the handler")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Errorf("expired session page: got %d %q", rec.Code, rec.Header().Get("Location"))
	}

	recAPI := httptest.NewRecorder()
	h.svc.RequireSession(true, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("expired session must not reach the API handler")
	})).ServeHTTP(recAPI, req)
	if recAPI.Code != http.StatusUnauthorized {
		t.Errorf("expired session API: status = %d, want 401", recAPI.Code)
	}
	// The expired cookie must be cleared.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("expired session cookie must be cleared")
	}
}

func TestNoSessionRedirectAnd401(t *testing.T) {
	h := newHarness(t, nil)
	rec := httptest.NewRecorder()
	h.svc.RequireSession(false, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login" {
		t.Errorf("no session page: got %d %q", rec.Code, rec.Header().Get("Location"))
	}

	recAPI := httptest.NewRecorder()
	h.svc.RequireSession(true, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(recAPI, httptest.NewRequest("GET", "/", nil))
	if recAPI.Code != http.StatusUnauthorized {
		t.Errorf("no session API: got %d, want 401", recAPI.Code)
	}
	if !strings.Contains(recAPI.Body.String(), `"error"`) {
		t.Error("API error must be JSON")
	}
}

func requireCSRFHarness(t *testing.T) (*harness, string) {
	t.Helper()
	h := newHarness(t, nil)
	value, err := h.svc.EncodeSession(Session{
		Username: "alice", Groups: []string{"admins"}, CSRFToken: "good-token",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return h, value
}

func TestCSRFRejection(t *testing.T) {
	h, sessionValue := requireCSRFHarness(t)
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("CSRF check must reject before the handler")
	})
	// The real middleware order: session first, then CSRF (the session
	// carries the expected token).
	chain := h.svc.RequireSession(true, h.svc.RequireCSRF(true, inner))

	// Foreign Origin.
	req := httptest.NewRequest("POST", "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionValue})
	req.Header.Set("Origin", "http://evil.example.com")
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("foreign origin: status = %d, want 403", rec.Code)
	}

	// Allowed origin but missing token.
	req = httptest.NewRequest("POST", "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionValue})
	req.Header.Set("Origin", h.srv.URL)
	rec = httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("missing token: status = %d, want 403", rec.Code)
	}

	// Wrong token.
	req = httptest.NewRequest("POST", "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionValue})
	req.Header.Set("Origin", h.srv.URL)
	req.Header.Set(CSRFHeader, "wrong-token")
	rec = httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong token: status = %d, want 403", rec.Code)
	}
}

func TestCSRFHeaderAndFormFieldAccepted(t *testing.T) {
	h, sessionValue := requireCSRFHarness(t)
	ok := false
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ok = true })
	chain := h.svc.RequireSession(true, h.svc.RequireCSRF(true, inner))

	req := httptest.NewRequest("POST", "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionValue})
	req.Header.Set(CSRFHeader, "good-token")
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !ok {
		t.Errorf("header CSRF accepted path failed: %d ok=%v", rec.Code, ok)
	}

	ok = false
	req = httptest.NewRequest("POST", "/logout", strings.NewReader("csrf_token=good-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionValue})
	rec = httptest.NewRecorder()
	h.svc.RequireSession(false, h.svc.RequireCSRF(false, inner)).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !ok {
		t.Errorf("form field CSRF accepted path failed: %d ok=%v", rec.Code, ok)
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	h, sessionValue := requireCSRFHarness(t)
	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionValue})
	req.Header.Set(CSRFHeader, "good-token")
	rec := httptest.NewRecorder()
	handler := h.svc.RequireSession(false, h.svc.RequireCSRF(false, http.HandlerFunc(h.svc.Logout)))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Errorf("logout: status = %d, location = %q", rec.Code, rec.Header().Get("Location"))
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("logout must clear the session cookie")
	}
}

func TestLogoutWithoutSession(t *testing.T) {
	h, _ := requireCSRFHarness(t)
	req := httptest.NewRequest("POST", "/logout", nil)
	rec := httptest.NewRecorder()
	handler := h.svc.RequireSession(false, h.svc.RequireCSRF(false, http.HandlerFunc(h.svc.Logout)))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Errorf("logout without session: status = %d, want 302", rec.Code)
	}
}

func TestPKCEShapes(t *testing.T) {
	ver, err := pkceVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if len(ver) != 43 {
		t.Errorf("verifier length = %d, want 43", len(ver))
	}
	sum := sha256.Sum256([]byte(ver))
	if got, want := pkceS256Challenge(ver), base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("challenge = %q, want base64url(sha256(verifier))", got)
	}
}

func TestDecodeSessionRejectsGarbage(t *testing.T) {
	h, _ := requireCSRFHarness(t)
	if _, err := h.svc.DecodeSession("not-a-cookie"); err == nil {
		t.Error("DecodeSession accepted garbage")
	}
}

func TestRedirectURIMaking(t *testing.T) {
	cfg := &config.Config{Server: config.Server{ExternalURL: "https://stacks.example.com"}}
	if got := redirectURI(cfg); got != "https://stacks.example.com/auth/callback" {
		t.Errorf("redirectURI = %q", got)
	}
	cfg.Server.ExternalURL = "https://example.com/stackctl/"
	if got := redirectURI(cfg); got != "https://example.com/stackctl/auth/callback" {
		t.Errorf("redirectURI with path = %q", got)
	}
}
