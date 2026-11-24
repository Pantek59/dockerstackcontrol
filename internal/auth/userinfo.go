package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

// fetchUserinfoClaims calls the provider's userinfo endpoint with the access
// token and returns the claims as a map. It returns (nil, nil) when the
// provider does not advertise a userinfo endpoint, so callers treat it as
// "no userinfo, stay with the ID token claims". Errors carry, via the usual
// wrapping, an OAuth2 error code (see oauth2ErrCode) that is safe to log.
func (s *Service) fetchUserinfoClaims(ctx context.Context, tok *oauth2.Token) (map[string]any, error) {
	endpoint := s.userinfoEndpoint()
	if endpoint == "" {
		return nil, nil
	}

	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(tok))
	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Read a bounded snippet of the body so the wrapped oauth2-style
		// error extraction can pick up an error code; the body itself is
		// never logged.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, &oauth2.RetrieveError{
			ErrorCode: extractErrorCode(body),
			Body:      body,
		}
	}

	var claims map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	if claims == nil {
		claims = map[string]any{}
	}
	return claims, nil
}

// oauth2ErrCode renders an error into something safe to audit: only the
// machine-readable OAuth2 error code, never raw response text (which some
// providers fill with echoed secrets or tokens).
func oauth2ErrCode(err error) string {
	if err == nil {
		return ""
	}
	var oer *oauth2.RetrieveError
	if errors.As(err, &oer) && oer.ErrorCode != "" {
		return oer.ErrorCode
	}
	return err.Error()
}

// extractErrorCode pulls "error" out of an OAuth2 JSON error body, if any.
func extractErrorCode(body []byte) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if code, ok := m["error"].(string); ok {
		return code
	}
	return ""
}
