package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"time"

	"golang.org/x/oauth2"
)

// Login starts the OIDC authorization code flow with PKCE: it generates
// state, nonce and code verifier, stores them in a short-lived signed cookie
// and redirects to the identity provider.
func (s *Service) Login(rw http.ResponseWriter, r *http.Request) {
	cfg := s.Holder.Get()

	// Already authenticated: no need to log in again.
	if sess, err := s.decodeSessionCookie(r); err == nil && !sess.Expired(time.Now()) {
		http.Redirect(rw, r, "/", http.StatusFound)
		return
	}

	oauth2Cfg, _, _, flowCodec := s.snapshot()

	state, err := randomToken(16)
	if err != nil {
		s.renderError(rw, r, http.StatusInternalServerError, "cannot generate state")
		return
	}
	nonce, err := randomToken(16)
	if err != nil {
		s.renderError(rw, r, http.StatusInternalServerError, "cannot generate nonce")
		return
	}
	verifier, err := pkceVerifier()
	if err != nil {
		s.renderError(rw, r, http.StatusInternalServerError, "cannot generate PKCE verifier")
		return
	}

	challenge := pkceS256Challenge(verifier)
	authURL := oauth2Cfg.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	fs := flowState{State: state, Nonce: nonce, Verifier: verifier, ExpiresAt: time.Now().Add(FlowCookieTTL)}
	encoded, err := flowCodec.Encode(FlowCookieName, fs)
	if err != nil {
		s.renderError(rw, r, http.StatusInternalServerError, "cannot encode login flow state")
		return
	}
	http.SetCookie(rw, &http.Cookie{
		Name:     FlowCookieName,
		Value:    encoded,
		Path:     "/",
		MaxAge:   int(FlowCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   cfg.Server.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(rw, r, authURL, http.StatusFound)
}

// Callback completes the flow: validates state, exchanges the code (with the
// PKCE verifier), verifies the ID token (signature, issuer, audience, expiry
// via go-oidc; nonce here) and creates the session cookie.
func (s *Service) Callback(rw http.ResponseWriter, r *http.Request) {
	cfg := s.Holder.Get()
	oauth2Cfg, verifier, _, flowCodec := s.snapshot()

	q := r.URL.Query()
	if errParam := q.Get("error"); errParam != "" {
		s.Audit.Login("unknown", false, s.remoteIP(r), "provider error: "+errParam)
		s.renderError(rw, r, http.StatusBadRequest, "login failed: provider returned an error")
		return
	}

	state := q.Get("state")
	if state == "" || q.Get("code") == "" {
		s.Audit.Login("unknown", false, s.remoteIP(r), "missing state or code")
		s.renderError(rw, r, http.StatusBadRequest, "login failed: missing parameters")
		return
	}

	flowCookie, err := r.Cookie(FlowCookieName)
	if err != nil || flowCookie.Value == "" {
		s.Audit.Login("unknown", false, s.remoteIP(r), "missing flow cookie")
		s.renderError(rw, r, http.StatusBadRequest, "login flow expired or missing cookie, start again")
		return
	}
	var fs flowState
	if err := flowCodec.Decode(FlowCookieName, flowCookie.Value, &fs); err != nil {
		s.Audit.Login("unknown", false, s.remoteIP(r), "invalid flow cookie")
		s.renderError(rw, r, http.StatusBadRequest, "login flow expired or corrupted, start again")
		return
	}
	if time.Now().After(fs.ExpiresAt) {
		s.Audit.Login("unknown", false, s.remoteIP(r), "flow cookie expired")
		s.renderError(rw, r, http.StatusBadRequest, "login flow expired, start again")
		return
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(fs.State)) != 1 {
		s.Audit.Login("unknown", false, s.remoteIP(r), "state mismatch")
		s.renderError(rw, r, http.StatusBadRequest, "login failed: state mismatch")
		return
	}

	ctx := r.Context()
	tok, err := oauth2Cfg.Exchange(ctx, q.Get("code"), oauth2.SetAuthURLParam("code_verifier", fs.Verifier))
	if err != nil {
		// Log the machine-readable error code only: some providers echo the
		// submitted secret (or other sensitive text) inside the human-readable
		// description, which must never reach the logs.
		detail := "token exchange failed"
		var oer *oauth2.RetrieveError
		if errors.As(err, &oer) && oer.ErrorCode != "" {
			detail += " (provider error: " + oer.ErrorCode + ")"
		}
		s.Audit.Login("unknown", false, s.remoteIP(r), detail)
		s.renderError(rw, r, http.StatusBadRequest, "login failed: token exchange failed")
		return
	}

	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		s.Audit.Login("unknown", false, s.remoteIP(r), "no id_token in token response")
		s.renderError(rw, r, http.StatusBadRequest, "login failed: no id_token")
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		s.Audit.Login("unknown", false, s.remoteIP(r), "id_token validation failed")
		s.renderError(rw, r, http.StatusBadRequest, "login failed: id_token invalid")
		return
	}

	claims := map[string]any{}
	if err := idToken.Claims(&claims); err != nil {
		s.Audit.Login("unknown", false, s.remoteIP(r), "unreadable claims")
		s.renderError(rw, r, http.StatusBadRequest, "login failed: unreadable claims")
		return
	}
	// The nonce must always be checked against the ID token alone, before
	// any claim merging.
	if nonce, _ := stringClaim(claims, "nonce"); nonce == "" || subtle.ConstantTimeCompare([]byte(nonce), []byte(fs.Nonce)) != 1 {
		s.Audit.Login("unknown", false, s.remoteIP(r), "nonce mismatch")
		s.renderError(rw, r, http.StatusBadRequest, "login failed: nonce mismatch")
		return
	}
	// Many providers (e.g. DocPouch) put profile claims such as the username
	// only in the userinfo endpoint, not in the ID token. Fetch it when the
	// discovery document advertises one and merge its claims; entries coming
	// from userinfo take precedence.
	if uiClaims, err := s.fetchUserinfoClaims(ctx, tok); err != nil {
		s.Audit.Login("unknown", false, s.remoteIP(r), "userinfo fetch skipped: "+oauth2ErrCode(err))
	} else {
		for k, v := range uiClaims {
			if v == nil || v == "" {
				continue
			}
			claims[k] = v
		}
	}

	username, _ := stringClaim(claims, cfg.OIDC.UsernameClaim)
	if username == "" {
		s.Audit.Login("unknown", false, s.remoteIP(r), "empty username claim "+cfg.OIDC.UsernameClaim)
		s.renderError(rw, r, http.StatusBadRequest, "login failed: identity has no username")
		return
	}
	groups := stringSliceClaim(claims, cfg.OIDC.GroupsClaim)

	if cfg.OIDC.RequiredGroup != "" && !slices.Contains(groups, cfg.OIDC.RequiredGroup) {
		s.Audit.Login(username, false, s.remoteIP(r), "missing required group "+cfg.OIDC.RequiredGroup)
		s.renderError(rw, r, http.StatusForbidden, "you are not allowed to use this application")
		return
	}

	sess := Session{
		Username:  username,
		Groups:    groups,
		ExpiresAt: time.Now().Add(cfg.Server.SessionTTL.Std()),
	}
	sess.CSRFToken, err = csrfToken()
	if err != nil {
		s.renderError(rw, r, http.StatusInternalServerError, "cannot generate CSRF token")
		return
	}

	_, _, sessionCodec, _ := s.snapshot()
	encoded, err := sessionCodec.Encode(SessionCookieName, sess)
	if err != nil {
		s.renderError(rw, r, http.StatusInternalServerError, "cannot create session")
		return
	}
	http.SetCookie(rw, s.sessionCookie(cfg, encoded, int(cfg.Server.SessionTTL.Std().Seconds())))
	http.SetCookie(rw, &http.Cookie{ // clear the flow cookie
		Name:     FlowCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   cfg.Server.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
	s.Audit.Login(username, true, s.remoteIP(r), "")
	http.Redirect(rw, r, "/", http.StatusFound)
}

// csrfToken generates the per-session CSRF token.
func csrfToken() (string, error) {
	return randomToken(32)
}

// Logout clears the session and redirects to /. It runs behind
// RequireSession(false) and RequireCSRF(false).
func (s *Service) Logout(rw http.ResponseWriter, r *http.Request) {
	cfg := s.Holder.Get()
	user, ok := UserFrom(r.Context())
	if !ok {
		http.Redirect(rw, r, "/", http.StatusFound)
		return
	}
	http.SetCookie(rw, s.sessionCookie(cfg, "", -1))
	s.Audit.Logout(user.Username, true, s.remoteIP(r))
	http.Redirect(rw, r, "/", http.StatusFound)
}

// randomToken returns base64url of n random bytes.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceVerifier produces a code verifier per RFC 7636: 32 random bytes give a
// 43 character base64url string, the minimum allowed length.
func pkceVerifier() (string, error) { return randomToken(32) }

// pkceS256Challenge derives the S256 code challenge from the verifier.
func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// stringClaim extracts a string claim.
func stringClaim(claims map[string]any, key string) (string, bool) {
	v, ok := claims[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

// stringSliceClaim extracts a claim that is either a string or a list of
// strings (providers differ), returning nil when absent or of neither shape.
func stringSliceClaim(claims map[string]any, key string) []string {
	v, ok := claims[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}
