package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Pantek59/dockerstackcontrol/internal/audit"
	"github.com/Pantek59/dockerstackcontrol/internal/auth"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
)

// fileConfig is a complete, valid configuration written to disk for reload
// tests. The rule set can be varied without changing the session keys.
const fileConfigFirst = `
server:
  listen: "127.0.0.1:0"
  external_url: "http://example.com"
  cookie_secure: false
  session_ttl: 1h
  session_hash_key: "__HASH__"
  session_block_key: "__BLOCK__"
oidc:
  issuer: "https://auth.example.com/realms/test"
  client_id: "stackctl"
  client_secret: "secret"
  scopes: ["openid"]
stacks:
  - {name: "media", label: "Media Server", project: "media"}
  - {name: "nextcloud", label: "Nextcloud", project: "nextcloud"}
rules:
  - subjects: {users: ["alice"], groups: ["admins"]}
    stacks: ["*"]
    actions: ["start", "stop", "restart"]
  - subjects: {users: ["bob"]}
    stacks: ["media"]
    actions: ["restart"]
`

func fileConfig(t *testing.T) (path string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "config.yaml")
	raw := strings.NewReplacer("__HASH__", testHashKey, "__BLOCK__", testBlockKey).Replace(fileConfigFirst)
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestReloadChangesAccessKeepsSessions verifies the acceptance criterion:
// changing the rules and reloading changes access for existing sessions
// without invalidating them (same session cookie keeps working).
func TestReloadChangesAccessKeepsSessions(t *testing.T) {
	path := fileConfig(t)

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	aud := audit.New(logger)
	holder, err := config.NewHolder(path)
	if err != nil {
		t.Fatalf("NewHolder: %v", err)
	}
	svc, err := auth.NewSessionService(holder, aud)
	if err != nil {
		t.Fatalf("NewSessionService: %v", err)
	}
	runner := newFakeRunner()
	s, err := New(holder, runner, svc, aud, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := s.Handler()

	// Mint a session for bob BEFORE the reload.
	value, err := svc.EncodeSession(auth.Session{
		Username: "bob", Groups: []string{}, CSRFToken: "csrf-bob",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(req *http.Request) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	getStacks := func(cookie string) stacksResponse {
		req, _ := http.NewRequest(http.MethodGet, base+"/api/stacks", nil)
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
		rec := do(req)
		if rec.Code != http.StatusOK {
			t.Fatalf("api/stacks status = %d, body %s", rec.Code, rec.Body.String())
		}
		var resp stacksResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	before := getStacks(value)
	if len(before.Stacks) != 1 || before.Stacks[0].Name != "media" {
		t.Fatalf("before reload: %+v", before.Stacks)
	}

	// Rewrite the file: add a new stack and widen bob to a wildcard; keep the keys.
	raw2 := `
server:
  listen: "127.0.0.1:0"
  external_url: "http://example.com"
  session_ttl: 1h
  session_hash_key: "` + testHashKey + `"
  session_block_key: "` + testBlockKey + `"
oidc:
  issuer: "https://auth.example.com/realms/test"
  client_id: "stackctl"
  client_secret: "secret"
stacks:
  - {name: "media", project: "media"}
  - {name: "nextcloud", project: "nextcloud"}
  - {name: "wiki", project: "wiki"}
rules:
  - subjects: {users: ["alice"]}
    stacks: ["nextcloud"]
    actions: ["start", "stop", "restart"]
  - subjects: {users: ["bob"]}
    stacks: ["*"]
    actions: ["start", "stop", "restart"]
`
	if err := os.WriteFile(path, []byte(raw2), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := holder.Reload(); err != nil {
		t.Fatalf("Reload: %v (mock provider must stay reachable for the reload hook)", err)
	}

	after := getStacks(value) // same session cookie, unchanged keys
	if len(after.Stacks) != 3 {
		t.Fatalf("after reload: bob's stacks = %+v, want all three (new wildcard rule)", after.Stacks)
	}
	names := []string{after.Stacks[0].Name, after.Stacks[1].Name, after.Stacks[2].Name}
	if names[0] != "media" || names[1] != "nextcloud" || names[2] != "wiki" {
		t.Errorf("after reload order = %v, want configuration order", names)
	}
}

// TestReloadKeepsOldConfigOnError ensures a broken file never takes effect.
func TestReloadKeepsOldConfigOnError(t *testing.T) {
	path := fileConfig(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	aud := audit.New(logger)
	holder, err := config.NewHolder(path)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := auth.NewSessionService(holder, aud)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(holder, newFakeRunner(), svc, aud, logger)
	if err != nil {
		t.Fatal(err)
	}
	before := holder.Get()

	if err := os.WriteFile(path, []byte("not: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := holder.Reload(); err == nil {
		t.Error("Reload accepted a broken file")
	}
	if holder.Get() != before {
		t.Error("failed reload must keep the previous configuration")
	}
	// The server keeps serving with the previous rules.
	req, _ := http.NewRequest(http.MethodGet, base+"/healthz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("healthz after failed reload = %d", rec.Code)
	}
}
