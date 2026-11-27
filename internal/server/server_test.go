package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Pantek59/dockerstackcontrol/internal/audit"
	"github.com/Pantek59/dockerstackcontrol/internal/auth"
	"github.com/Pantek59/dockerstackcontrol/internal/config"
	"github.com/Pantek59/dockerstackcontrol/internal/docker"
)

var (
	testHashKey  = base64.StdEncoding.EncodeToString(repeat(64, 0x5A))
	testBlockKey = base64.StdEncoding.EncodeToString(repeat(32, 0x3B))
)

func repeat(n int, v byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = v
	}
	return b
}

func testConfig() *config.Config {
	return &config.Config{
		Server: config.Server{
			Listen:          "127.0.0.1:0",
			ExternalURL:     "http://example.com",
			CookieSecure:    false,
			SessionTTL:      config.Duration(time.Hour),
			CommandTimeout:  config.Duration(5 * time.Second),
			SessionHashKey:  testHashKey,
			SessionBlockKey: testBlockKey,
		},
		OIDC: config.OIDC{
			Issuer:        "https://auth.example.com/realms/test",
			ClientID:      "stackctl",
			ClientSecret:  "secret",
			Scopes:        []string{"openid", "profile", "groups"},
			UsernameClaim: "preferred_username",
			GroupsClaim:   "groups",
		},
		Docker: config.Docker{
			ComposeBinary: "docker",
			PullTimeout:   config.Duration(30 * time.Second),
		},
		Stacks: []config.Stack{
			{Name: "media", Label: "Media Server", Project: "media"},
			{Name: "nextcloud", Label: "Nextcloud", Project: "nextcloud"},
		},
		Rules: []config.Rule{
			{
				Subjects: config.SubjectSet{Users: []string{"alice"}, Groups: []string{"admins"}},
				Stacks:   []string{"*"},
				Actions:  []string{"start", "stop", "restart", "pull", "up", "edit"},
			},
			{
				Subjects: config.SubjectSet{Users: []string{"bob"}, Groups: []string{"family"}},
				Stacks:   []string{"media"},
				Actions:  []string{"restart"},
			},
		},
	}
}

// fakeRunner implements docker.Runner.
type fakeRunner struct {
	mu          sync.Mutex
	statuses    map[string]docker.StackStatus
	statusEr    map[string]error
	doErr       map[string]error
	validateErr map[string]error
	doDelay     time.Duration
	calls       []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		statuses:    map[string]docker.StackStatus{},
		statusEr:    map[string]error{},
		doErr:       map[string]error{},
		validateErr: map[string]error{},
	}
}

func (f *fakeRunner) Status(ctx context.Context, project string) (docker.StackStatus, error) {
	f.mu.Lock()
	err := f.statusEr[project]
	st, ok := f.statuses[project]
	f.calls = append(f.calls, "status:"+project)
	f.mu.Unlock()
	if err != nil {
		return docker.StackStatus{}, err
	}
	if ok {
		return st, nil
	}
	return docker.StackStatus{State: docker.StateNotFound, Services: []docker.Service{}}, nil
}

func (f *fakeRunner) Do(ctx context.Context, spec docker.StackSpec, action docker.Action) error {
	if f.doDelay > 0 {
		time.Sleep(f.doDelay)
	}
	key := spec.Project + "/" + string(action)
	if spec.Compose != "" {
		key += "@" + spec.Compose
	}
	f.mu.Lock()
	err := f.doErr[key]
	f.calls = append(f.calls, "do:"+key)
	f.mu.Unlock()
	return err
}

func (f *fakeRunner) Validate(ctx context.Context, spec docker.StackSpec) error {
	f.mu.Lock()
	err := f.validateErr[spec.Project]
	f.calls = append(f.calls, "validate:"+spec.Project+"/"+spec.Compose)
	f.mu.Unlock()
	return err
}

func (f *fakeRunner) callsWith(prefix string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			out = append(out, c)
		}
	}
	return out
}

// harness wires the server with a fake runner inside one test process.
type harness struct {
	handler http.Handler
	runner  *fakeRunner
	svc     *auth.Service
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()

	cfg := testConfig()
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("test config invalid: %v", err)
	}

	runner := newFakeRunner()
	aud := audit.New(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	holder := config.NewStaticHolder(cfg)
	svc, err := auth.NewSessionService(holder, aud)
	if err != nil {
		t.Fatalf("NewSessionService: %v", err)
	}
	s, err := New(holder, runner, svc, aud, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return &harness{handler: s.Handler(), runner: runner, svc: svc}
}

// sessionFor mints a session cookie for a user.
func (h *harness) sessionFor(t *testing.T, username string, groups []string) (cookieValue, csrfToken string) {
	t.Helper()
	csrf := "csrf-" + username
	value, err := h.svc.EncodeSession(auth.Session{
		Username:  username,
		Groups:    groups,
		CSRFToken: csrf,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return value, csrf
}

// do runs a request through the handler and returns the response.
func (h *harness) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func get(t *testing.T, target string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func post(t *testing.T, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

const base = "http://example.com"

// withSession attaches the session cookie and, when token is non-empty, the
// CSRF header and a matching Origin header.
func withSession(req *http.Request, cookie, csrf, origin string) *http.Request {
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
	if csrf != "" {
		req.Header.Set(auth.CSRFHeader, csrf)
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return req
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("response not JSON: %v\n%s", err, rec.Body.String())
	}
	return m
}

func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, want, rec.Body.String())
	}
}

func TestHealthz(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.do(get(t, base+"/healthz"))
	requireStatus(t, rec, http.StatusOK)
	if strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Errorf("healthz body = %q, want ok", rec.Body.String())
	}
	if len(h.runner.callsWith("")) != 0 {
		t.Error("healthz must not call docker")
	}
}

func TestNoSessionBehaviours(t *testing.T) {
	h := newHarness(t, nil)

	rec := h.do(get(t, base+"/"))
	requireStatus(t, rec, http.StatusFound)
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("dashboard redirect = %q, want /login", loc)
	}

	rec = h.do(get(t, base+"/api/stacks"))
	requireStatus(t, rec, http.StatusUnauthorized)
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Error("API 401 must be JSON")
	}
}

func TestAPIStacksAsAdmin(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Stacks[0].Project = "media"
	})
	h.runner.statuses["media"] = docker.StackStatus{
		State: docker.StateRunning,
		Services: []docker.Service{
			{Name: "jellyfin", State: "running"},
		},
	}
	h.runner.statuses["nextcloud"] = docker.StackStatus{
		State: docker.StateStopped,
		Services: []docker.Service{
			{Name: "app", State: "exited"},
		},
	}

	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(get(t, base+"/api/stacks"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)

	var resp struct {
		User      string `json:"user"`
		CSRFToken string `json:"csrf_token"`
		Stacks    []struct {
			Name     string `json:"name"`
			Label    string `json:"label"`
			State    string `json:"state"`
			Services []struct {
				Name  string `json:"name"`
				State string `json:"state"`
			} `json:"services"`
			AllowedActions []string `json:"allowed_actions"`
		} `json:"stacks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, rec.Body.String())
	}
	if resp.User != "alice" || resp.CSRFToken != csrf {
		t.Errorf("user/csrf = %q/%q", resp.User, resp.CSRFToken)
	}
	if len(resp.Stacks) != 2 {
		t.Fatalf("stacks = %d, want 2 (configuration order)", len(resp.Stacks))
	}
	media := resp.Stacks[0]
	if media.Name != "media" || media.Label != "Media Server" || media.State != "running" {
		t.Errorf("media entry = %+v", media)
	}
	// File-backed actions (pull, up, edit) are granted by the rule but
	// filtered out here: test stacks declare no directory.
	if len(media.AllowedActions) != 3 ||
		media.AllowedActions[0] != "start" || media.AllowedActions[1] != "stop" || media.AllowedActions[2] != "restart" {
		t.Errorf("allowed_actions = %v, want [start stop restart] (no dir configured)", media.AllowedActions)
	}
	if len(media.Services) != 1 || media.Services[0].Name != "jellyfin" || media.Services[0].State != "running" {
		t.Errorf("media services = %+v", media.Services)
	}
	if nc := resp.Stacks[1]; nc.Name != "nextcloud" || nc.State != "stopped" {
		t.Errorf("nextcloud entry = %+v", nc)
	}
}

func TestAPIStacksAsBobSeesOnlyMedia(t *testing.T) {
	h := newHarness(t, nil)
	cookie, csrf := h.sessionFor(t, "bob", []string{"family"})
	rec := h.do(withSession(get(t, base+"/api/stacks"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)

	var resp stacksResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.User != "bob" {
		t.Errorf("user = %q", resp.User)
	}
	if len(resp.Stacks) != 1 || resp.Stacks[0].Name != "media" {
		t.Fatalf("stacks = %+v, want only media", resp.Stacks)
	}
	if got := resp.Stacks[0].AllowedActions; len(got) != 1 || got[0] != "restart" {
		t.Errorf("allowed_actions = %v, want [restart]", got)
	}
}

func TestAPIStacksUserWithoutRulesSeesEmptyList(t *testing.T) {
	h := newHarness(t, nil)
	cookie, csrf := h.sessionFor(t, "carol", nil)
	rec := h.do(withSession(get(t, base+"/api/stacks"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)

	var resp stacksResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Stacks == nil || len(resp.Stacks) != 0 {
		t.Errorf("stacks = %v, want empty non-nil list", resp.Stacks)
	}
}

func TestActionDeniedForDisallowedActionNoCall(t *testing.T) {
	h := newHarness(t, nil)
	cookie, csrf := h.sessionFor(t, "bob", []string{"family"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/stop", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusForbidden)
	if body := decodeBody(t, rec); body["error"] != "action not allowed" {
		t.Errorf("error = %v", body["error"])
	}
	if calls := h.runner.callsWith("do:"); len(calls) != 0 {
		t.Errorf("executed docker calls: %v — nothing must run without permission", calls)
	}
}

func TestActionInvisibleAndUnknownStackReturn404NoCall(t *testing.T) {
	h := newHarness(t, nil)
	bobCookie, bobCSRF := h.sessionFor(t, "bob", []string{"family"})
	aliceCookie, aliceCSRF := h.sessionFor(t, "alice", []string{"admins"})

	// Invisible stack (bob has no permission on nextcloud).
	rec := h.do(withSession(post(t, base+"/api/stacks/nextcloud/start", nil), bobCookie, bobCSRF, "http://example.com"))
	requireStatus(t, rec, http.StatusNotFound)

	// Unknown stack name (never declared).
	rec = h.do(withSession(post(t, base+"/api/stacks/ghost/start", nil), aliceCookie, aliceCSRF, "http://example.com"))
	requireStatus(t, rec, http.StatusNotFound)

	if calls := h.runner.callsWith("do:"); len(calls) != 0 {
		t.Errorf("executed docker calls: %v", calls)
	}
}

// updateStackConfig grants "update" on all stacks; dir optionally points the
// stacks at a directory that must contain model compose.
func updateStackConfig(dir string) func(*config.Config) {
	return func(c *config.Config) {
		c.Stacks[0].Dir = dir
		c.Rules[0].Actions = append(c.Rules[0].Actions, "update")
	}
}

func TestUpdateActionRunsAsOneRequest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, updateStackConfig(dir))
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/update", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusOK)

	// The file-backed update reached the runner with the resolved model.
	calls := h.runner.callsWith("do:")
	if len(calls) != 1 || calls[0] != "do:media/update@docker-compose.yml" {
		t.Fatalf("executed docker calls = %v, want exactly [do:media/update@docker-compose.yml]", calls)
	}

	var entry stackJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, rec.Body.String())
	}
	if entry.Warning != "" {
		t.Errorf("warning = %q, want empty on success", entry.Warning)
	}
	if got, want := entry.AllowedActions, []string{"start", "stop", "restart", "pull", "up", "update", "edit"}; !slices.Equal(got, want) {
		t.Errorf("allowed_actions = %v, want %v (dir is now set)", got, want)
	}
}

func TestUpdateDeniedWithoutGrantOrWithoutDir(t *testing.T) {
	// bob holds "restart" only; even with a dir he gets 403.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *config.Config) { c.Stacks[0].Dir = dir })
	cookie, csrf := h.sessionFor(t, "bob", []string{"family"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/update", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusForbidden)
	if calls := h.runner.callsWith("do:"); len(calls) != 0 {
		t.Errorf("executed docker calls: %v — nothing must run without permission", calls)
	}

	// alice holds update, but the stack declares no directory: 400 after the
	// permission checks, still without touching the daemon.
	h2 := newHarness(t, updateStackConfig(""))
	cookie2, csrf2 := h2.sessionFor(t, "alice", []string{"admins"})
	rec2 := h2.do(withSession(post(t, base+"/api/stacks/media/update", nil), cookie2, csrf2, "http://example.com"))
	requireStatus(t, rec2, http.StatusBadRequest)
	if calls := h2.runner.callsWith("do:"); len(calls) != 0 {
		t.Errorf("executed docker calls: %v — the dir guard runs before any command", calls)
	}
}

func TestUpdatePullFailureSurfacesAsWarning(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, updateStackConfig(dir))
	h.runner.doErr["media/update@docker-compose.yml"] = &docker.UpdateError{
		PullErr: &docker.CommandError{Command: "docker compose -p media -f compose pull", ExitCode: 1, Stderr: "SECRET-registry-unreachable"},
	}
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/update", nil), cookie, csrf, "http://example.com"))
	// The recreation step ran and succeeded: overall success with a warning.
	requireStatus(t, rec, http.StatusOK)

	var entry stackJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, rec.Body.String())
	}
	if !strings.Contains(entry.Warning, "image pull failed") {
		t.Errorf("warning = %q, want the sanitized pull failure", entry.Warning)
	}
	if strings.Contains(entry.Warning, "SECRET") || strings.Contains(entry.Warning, "registry-unreachable") {
		t.Errorf("warning leaks command stderr: %q", entry.Warning)
	}
}

func TestActionCSRFRequired(t *testing.T) {
	h := newHarness(t, nil)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})

	// No CSRF token.
	req := withSession(post(t, base+"/api/stacks/media/restart", nil), cookie, "", "")
	rec := h.do(req)
	requireStatus(t, rec, http.StatusForbidden)

	// Wrong CSRF token.
	req = withSession(post(t, base+"/api/stacks/media/restart", nil), cookie, "wrong", "")
	rec = h.do(req)
	requireStatus(t, rec, http.StatusForbidden)

	// Foreign Origin.
	req = withSession(post(t, base+"/api/stacks/media/restart", nil), cookie, csrf, "http://evil.example.com")
	rec = h.do(req)
	requireStatus(t, rec, http.StatusForbidden)

	if calls := h.runner.callsWith("do:"); len(calls) != 0 {
		t.Errorf("executed docker calls: %v — CSRF must gate before any Docker call", calls)
	}
}

func TestActionSuccessReturnsNewStatus(t *testing.T) {
	h := newHarness(t, nil)
	h.runner.statuses["media"] = docker.StackStatus{
		State:    docker.StateRunning,
		Services: []docker.Service{{Name: "jellyfin", State: "running"}},
	}
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/restart", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusOK)

	var entry stackJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Name != "media" || entry.State != "running" || entry.Label != "Media Server" {
		t.Errorf("response = %+v", entry)
	}
	if len(entry.Services) != 1 || entry.Services[0].Name != "jellyfin" {
		t.Errorf("services = %+v", entry.Services)
	}
	calls := h.runner.callsWith("do:media/restart")
	if len(calls) != 1 {
		t.Errorf("do calls = %v, want exactly one restart", calls)
	}
	// Status must be queried after the action.
	statuses := h.runner.callsWith("status:media")
	if len(statuses) < 1 {
		t.Error("status must be queried after the action")
	}
}

func TestExpirySessions(t *testing.T) {
	h := newHarness(t, nil)
	value, err := h.svc.EncodeSession(auth.Session{
		Username: "alice", CSRFToken: "x", ExpiresAt: time.Now().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := h.do(withSession(get(t, base+"/api/stacks"), value, "", ""))
	requireStatus(t, rec, http.StatusUnauthorized)
}

func TestActionTimeoutAndCommandError(t *testing.T) {
	h := newHarness(t, nil)
	h.runner.doErr["media/restart"] = fmt.Errorf("%w: docker compose -p media restart", docker.ErrTimeout)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/restart", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusGatewayTimeout)

	h.runner.doErr["media/restart"] = &docker.CommandError{
		Command:  "docker compose -p media restart",
		ExitCode: 1,
		Stderr:   "secret stderr content",
	}
	rec = h.do(withSession(post(t, base+"/api/stacks/media/restart", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusBadGateway)
	if strings.Contains(rec.Body.String(), "secret stderr content") {
		t.Error("command stderr must not leak into the response")
	}
}

func TestStatusErrorAfterActionStillOK(t *testing.T) {
	h := newHarness(t, nil)
	h.runner.statusEr["media"] = errors.New("boom")
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/restart", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusOK)

	var entry stackJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.State != docker.StateUnknown {
		t.Errorf("state = %q, want unknown", entry.State)
	}
	if len(entry.Services) != 0 {
		t.Errorf("services = %+v, want empty", entry.Services)
	}
}

func TestConcurrentActionReturnsConflict(t *testing.T) {
	h := newHarness(t, nil)
	h.runner.doDelay = 300 * time.Millisecond
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})

	// Fire one sessioned request, then a second while the first is still
	// running.
	var wg sync.WaitGroup
	results := make(chan int, 2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		results <- h.do(withSession(post(t, base+"/api/stacks/media/restart", nil), cookie, csrf, "http://example.com")).Code
	}()
	time.Sleep(80 * time.Millisecond)
	results <- h.do(withSession(post(t, base+"/api/stacks/media/restart", nil), cookie, csrf, "http://example.com")).Code
	wg.Wait()
	close(results)

	codes := map[int]int{}
	for c := range results {
		codes[c]++
	}
	if codes[http.StatusOK] != 1 || codes[http.StatusConflict] != 1 {
		t.Errorf("codes = %v, want exactly one 200 and one 409", codes)
	}
	if calls := h.runner.callsWith("do:media/restart"); len(calls) != 1 {
		t.Errorf("do calls = %d, want exactly one executed", len(calls))
	}
}

func TestDashboardRenders(t *testing.T) {
	h := newHarness(t, nil)
	cookie, csrf := h.sessionFor(t, "bob", []string{"family"})
	rec := h.do(withSession(get(t, base+"/"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)
	body := rec.Body.String()
	for _, want := range []string{
		"Stack Control",
		"data-csrf-token=\"" + csrf + "\"",
		"bob",
		`action="/logout"`,
		"csrf_token",
		"/static/app.js",
		"/static/style.css",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	// The CSRF token must appear inside the logout form hidden input too.
	if !strings.Contains(body, `value="`+csrf+`"`) {
		t.Error("logout form must carry the CSRF token")
	}
}

func TestErrorPageForUnknownPath(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.do(get(t, base+"/nope"))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "404") || !strings.Contains(rec.Body.String(), "Stack Control") {
		t.Error("404 must render the HTML error page")
	}
}

func TestStaticAssetsServed(t *testing.T) {
	h := newHarness(t, nil)
	for _, c := range []struct {
		path        string
		contentType string
		mustContain string
	}{
		{"/static/app.js", "text/javascript", "api/stacks"},
		{"/static/style.css", "text/css", "prefers-color-scheme"},
		{"/static/favicon.svg", "image/svg+xml", "</svg>"},
	} {
		rec := h.do(get(t, base+c.path))
		requireStatus(t, rec, http.StatusOK)
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, c.contentType) {
			t.Errorf("%s content-type = %q, want prefix %q", c.path, ct, c.contentType)
		}
		if !strings.Contains(rec.Body.String(), c.mustContain) {
			t.Errorf("%s does not contain %q", c.path, c.mustContain)
		}
	}
	if rec := h.do(get(t, base+"/static/nope.css")); rec.Code != http.StatusNotFound {
		t.Errorf("missing asset status = %d, want 404", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.do(get(t, base+"/healthz"))
	requireStatus(t, rec, http.StatusOK)
	checks := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "same-origin",
		"X-Frame-Options":         "DENY",
	}
	for name, want := range checks {
		if got := rec.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestUnknownAPIPathAndWrongMethod(t *testing.T) {
	h := newHarness(t, nil)

	rec := h.do(get(t, base+"/api/unknown"))
	requireStatus(t, rec, http.StatusNotFound)
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Error("API 404 must be JSON")
	}

	rec = h.do(post(t, base+"/api/stacks", nil)) // POST to a GET-only endpoint
	requireStatus(t, rec, http.StatusMethodNotAllowed)
	if allow := rec.Header().Get("Allow"); allow != "GET" {
		t.Errorf("Allow = %q, want GET", allow)
	}

	rec = h.do(get(t, base+"/api/stacks/media/restart")) // GET on POST-only route
	requireStatus(t, rec, http.StatusMethodNotAllowed)
	if allow := rec.Header().Get("Allow"); allow != "POST" {
		t.Errorf("Allow = %q, want POST", allow)
	}
}

func TestRemoteIPWithTrustedProxies(t *testing.T) {
	cfg := testConfig()
	cfg.Server.TrustedProxies = []string{"10.0.0.0/8", "192.168.6.6"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, base+"/", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := RemoteIP(cfg, req); got != "203.0.113.7" {
		t.Errorf("trusted proxy XFF = %q, want 203.0.113.7", got)
	}

	req.Header.Del("X-Forwarded-For")
	if got := RemoteIP(cfg, req); got != "10.1.2.3" {
		t.Errorf("trusted proxy without XFF = %q, want peer 10.1.2.3", got)
	}

	req.RemoteAddr = "203.0.113.9:4444" // not trusted
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := RemoteIP(cfg, req); got != "203.0.113.9" {
		t.Errorf("untrusted peer XFF = %q, want peer 203.0.113.9", got)
	}

	// Bare IP entry (192.168.6.6, no mask) is treated as a /32.
	req.RemoteAddr = "192.168.6.6:1"
	req.Header.Del("X-Forwarded-For")
	if got := RemoteIP(cfg, req); got != "192.168.6.6" {
		t.Errorf("bare-ip trusted peer = %q", got)
	}
	// ...and its header IS honored when present.
	req.Header.Set("X-Forwarded-For", "198.51.100.4")
	if got := RemoteIP(cfg, req); got != "198.51.100.4" {
		t.Errorf("bare-ip trusted proxy XFF = %q, want 198.51.100.4", got)
	}
}

func TestRemoteIPWithoutTrustedProxiesIgnoresHeader(t *testing.T) {
	cfg := testConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, base+"/", nil)
	req.RemoteAddr = "198.18.0.1:9999"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	if got := RemoteIP(cfg, req); got != "198.18.0.1" {
		t.Errorf("remote ip = %q, want direct peer when no proxies are trusted", got)
	}
}

func TestStacksEndpointDoesNotLeakSessionExpiryToBody(t *testing.T) {
	h := newHarness(t, nil)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(get(t, base+"/api/stacks"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)
	if strings.Contains(rec.Body.String(), "expires") {
		t.Error("response must not leak internal session fields")
	}
}
