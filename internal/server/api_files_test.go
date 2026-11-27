package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pantek59/dockerstackcontrol/internal/config"
)

// stackDirHarness wires a harness whose "media" stack declares a directory
// containing a compose model. Returns the harness, the stack directory and
// the compose file path inside it.
func stackDirHarness(t *testing.T) (*harness, string, string) {
	t.Helper()
	dir := t.TempDir()
	compose := dir + "/docker-compose.yml"
	if err := os.WriteFile(compose, []byte("services:\n  app:\n    image: nginx:1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, func(c *config.Config) {
		c.Stacks[0].Dir = dir
	})
	return h, dir, compose
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func readTestFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// --- files listing ---------------------------------------------------------

func TestFilesListWithDir(t *testing.T) {
	h, dir, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(get(t, base+"/api/stacks/media/files"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)

	var resp filesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, rec.Body.String())
	}
	if resp.Stack != "media" || !resp.HasDir || resp.Dir != dir {
		t.Errorf("response head = %+v", resp)
	}
	if len(resp.Files) != 2 {
		t.Fatalf("files = %d, want 2", len(resp.Files))
	}
	compose, env := resp.Files[0], resp.Files[1]
	if compose.Kind != "compose" || !compose.Exists || compose.Name != "docker-compose.yml" || compose.Size == 0 {
		t.Errorf("compose entry = %+v", compose)
	}
	if env.Kind != "env" || env.Exists {
		t.Errorf("env entry = %+v, want absent", env)
	}
}

func TestFilesListWithoutDirIsEmpty(t *testing.T) {
	h := newHarness(t, nil) // stacks without Dir configured
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(get(t, base+"/api/stacks/nextcloud/files"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)

	var resp filesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.HasDir || len(resp.Files) != 0 {
		t.Errorf("response = %+v, want has_dir=false and no files", resp)
	}
}

func TestFilesListDeniedWithoutEditPermission(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "bob", []string{"family"}) // restart only
	rec := h.do(withSession(get(t, base+"/api/stacks/media/files"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusForbidden)
}

func TestFilesListInvisibleStackIs404(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "bob", []string{"family"})
	rec := h.do(withSession(get(t, base+"/api/stacks/nextcloud/files"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusNotFound)
}

// --- file read -------------------------------------------------------------

func TestFileReadReturnsContentAndHash(t *testing.T) {
	h, _, compose := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(get(t, base+"/api/stacks/media/files/compose"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)

	var resp contentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Exists || resp.Hash == "" || !strings.Contains(resp.Text, "nginx:1") {
		t.Errorf("read = %+v", resp)
	}
	raw, _ := readTestFile(compose)
	if resp.Hash != sha256Hex(raw) {
		t.Error("hash does not match the on-disk content")
	}

	// Absent file: scaffold, empty hash.
	rec = h.do(withSession(get(t, base+"/api/stacks/media/files/env"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)
	resp = contentResponse{}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Exists || resp.DefaultContent == "" {
		t.Errorf("absent env read = %+v, want scaffold", resp)
	}
}

func TestFileReadUnknownKindIs404(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(get(t, base+"/api/stacks/media/files/bogus"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusNotFound)
}

// --- file save -------------------------------------------------------------

func putFile(h *harness, cookie, csrf, kind, body string) (int, *contentResponse) {
	req, err := http.NewRequest(http.MethodPut, base+"/api/stacks/media/files/"+kind, strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := h.do(withSession(req, cookie, csrf, "http://example.com"))
	var resp contentResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec.Code, &resp
}

func TestFileSaveHappyPath(t *testing.T) {
	h, dir, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})

	// Create the .env from scratch (empty base hash for an absent file).
	code, resp := putFile(h, cookie, csrf, "env", `{"content":"KEY=v\n","base_hash":""}`)
	if code != http.StatusOK {
		t.Fatalf("create .env status = %d (%s)", code, recBody(resp))
	}
	raw, _ := readTestFile(dir + "/.env")
	if string(raw) != "KEY=v\n" {
		t.Fatalf(".env = %q after create", raw)
	}
	if resp.Hash != sha256Hex(raw) {
		t.Error("returned hash mismatch")
	}

	// Update with the attested hash.
	code, _ = putFile(h, cookie, csrf, "env",
		fmt.Sprintf(`{"content":"KEY=v2\n","base_hash":%q}`, resp.Hash))
	if code != http.StatusOK {
		t.Fatalf("update .env status = %d", code)
	}
	raw, _ = readTestFile(dir + "/.env")
	if string(raw) != "KEY=v2\n" {
		t.Fatalf(".env = %q after update", raw)
	}
	if calls := h.runner.callsWith("do:"); len(calls) != 0 {
		t.Errorf("saving a file must not run any docker command: %v", calls)
	}
}

func TestFileSaveValidatesComposeBeforeWriting(t *testing.T) {
	h, dir, compose := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})

	code, resp := putFile(h, cookie, csrf, "compose",
		fmt.Sprintf(`{"content":"services:\n  app:\n    image: nginx:2\n","base_hash":%q}`,
			sha256Hex([]byte("services:\n  app:\n    image: nginx:1\n"))))
	if code != http.StatusOK {
		t.Fatalf("save status = %d", code)
	}
	raw, _ := readTestFile(compose)
	if !strings.Contains(string(raw), "nginx:2") {
		t.Fatalf("compose = %q after save", raw)
	}
	// Validation ran exactly once, against a temporary copy inside the
	// stack directory, and the fake saw the project name.
	calls := h.runner.callsWith("validate:media/")
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "validate:media/stackctl-val-") {
		t.Errorf("validate calls = %v", calls)
	}
	if resp.Hash != sha256Hex(raw) {
		t.Error("returned hash mismatch")
	}
	// No leftover validation or write temp files.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "stackctl-val-") || strings.HasPrefix(e.Name(), ".stackctl-tmp-") {
			t.Errorf("leftover temp file %q", e.Name())
		}
	}
}

func TestFileSaveComposeValidationFailure(t *testing.T) {
	h, _, compose := stackDirHarness(t)
	h.runner.validateErr["media"] = fmt.Errorf("compose: validation error (server-side detail)")
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})

	req, _ := http.NewRequest(http.MethodPut, base+"/api/stacks/media/files/compose",
		strings.NewReader(fmt.Sprintf(
			`{"content":"services:\n  app:\n    image: nginx:2\n","base_hash":%q}`,
			sha256Hex([]byte("services:\n  app:\n    image: nginx:1\n")))))
	req.Header.Set("Content-Type", "application/json")
	rec := h.do(withSession(req, cookie, csrf, "http://example.com"))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("save status = %d, want 422", rec.Code)
	}
	raw, _ := readTestFile(compose)
	if strings.Contains(string(raw), "nginx:2") {
		t.Error("a failing validation must not change the file")
	}
	// The compose error detail must not leak into the response.
	if strings.Contains(rec.Body.String(), "server-side detail") {
		t.Error("validation detail leaked into the response")
	}
	if !strings.Contains(rec.Body.String(), "compose validation failed") {
		t.Errorf("error message = %s", rec.Body.String())
	}
}

func TestFileSaveConflict(t *testing.T) {
	h, dir, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})

	code, _ := putFile(h, cookie, csrf, "env", `{"content":"A=1\n","base_hash":""}`)
	if code != http.StatusOK {
		t.Fatalf("first save status = %d", code)
	}
	// Stale hash.
	code, _ = putFile(h, cookie, csrf, "env",
		fmt.Sprintf(`{"content":"A=2\n","base_hash":%q}`, sha256Hex([]byte("stale\n"))))
	if code != http.StatusConflict {
		t.Fatalf("stale hash status = %d, want 409", code)
	}
	// Empty hash on an existing file.
	code, _ = putFile(h, cookie, csrf, "env", `{"content":"A=3\n","base_hash":""}`)
	if code != http.StatusConflict {
		t.Fatalf("empty hash status = %d, want 409", code)
	}
	raw, _ := readTestFile(dir + "/.env")
	if string(raw) != "A=1\n" {
		t.Errorf(".env = %q, conflicts must not modify the file", raw)
	}
}

func TestFileSaveRequiresCSRF(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	cookie, _ := h.sessionFor(t, "alice", []string{"admins"})

	req, _ := http.NewRequest(http.MethodPut, base+"/api/stacks/media/files/env",
		strings.NewReader(`{"content":"A=1\n","base_hash":""}`))
	req.Header.Set("Content-Type", "application/json")
	rec := h.do(withSession(req, cookie, "", "")) // no CSRF header
	requireStatus(t, rec, http.StatusForbidden)
	if fileExists(dir(h) + "/.env") {
		t.Error("file must not exist after CSRF rejection")
	}
}

func TestFileSaveNoSession(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	req, _ := http.NewRequest(http.MethodPut, base+"/api/stacks/media/files/env",
		strings.NewReader(`{"content":"A=1\n","base_hash":""}`))
	rec := h.do(req)
	requireStatus(t, rec, http.StatusUnauthorized)
}

func TestFileSaveBobForbidden(t *testing.T) {
	h, dir, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "bob", []string{"family"})
	req, _ := http.NewRequest(http.MethodPut, base+"/api/stacks/media/files/env",
		strings.NewReader(`{"content":"A=1\n","base_hash":""}`))
	rec := h.do(withSession(req, cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusForbidden)
	if fileExists(dir + "/.env") {
		t.Error("file must not exist after a denial")
	}
}

func TestFileSaveBadBody(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	req, _ := http.NewRequest(http.MethodPut, base+"/api/stacks/media/files/env",
		strings.NewReader("not json"))
	rec := h.do(withSession(req, cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusBadRequest)
}

// --- pull / up actions ------------------------------------------------------

func TestPullAndUpActionsRunThroughStackSpec(t *testing.T) {
	h, _, compose := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})

	for _, action := range []string{"pull", "up"} {
		rec := h.do(withSession(post(t, base+"/api/stacks/media/"+action, nil), cookie, csrf, "http://example.com"))
		requireStatus(t, rec, http.StatusOK)
	}

	// spec.Compose reaches the runner as the plain file name (the ExecRunner
	// contract; it joins and re-validates it against spec.Dir itself).
	name := filepath.Base(compose)
	calls := h.runner.callsWith("do:media/")
	if len(calls) != 2 {
		t.Fatalf("do calls = %v, want pull and up", calls)
	}
	if !strings.HasPrefix(calls[0], "do:media/pull@") || !strings.HasSuffix(calls[0], "@"+name) {
		t.Errorf("pull call = %q, want the resolved compose file name %q", calls[0], name)
	}
	if !strings.HasPrefix(calls[1], "do:media/up@") || !strings.HasSuffix(calls[1], "@"+name) {
		t.Errorf("up call = %q, want the resolved compose file name %q", calls[1], name)
	}
}

func TestPullWithoutDirIsRejectedBeforeExec(t *testing.T) {
	h := newHarness(t, nil) // nextcloud has no Dir
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(post(t, base+"/api/stacks/nextcloud/pull", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusBadRequest)
	if calls := h.runner.callsWith("do:"); len(calls) != 0 {
		t.Errorf("docker ran despite missing dir: %v", calls)
	}
}

func TestPullWithMissingComposeFileIsRejected(t *testing.T) {
	dir := t.TempDir() // empty directory: no compose model inside
	h := newHarness(t, func(c *config.Config) {
		c.Stacks[0].Dir = dir
	})
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/pull", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusBadRequest)
	if calls := h.runner.callsWith("do:"); len(calls) != 0 {
		t.Error("docker ran despite a missing compose file")
	}
}

func TestPullDeniedForBob(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "bob", []string{"family"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/pull", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusForbidden)
}

func TestEditActionHasNoEndpoint(t *testing.T) {
	// "edit" is a permission for the editor page and its file API; the
	// action endpoint must not pretend to run it.
	h, _, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(post(t, base+"/api/stacks/media/edit", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusNotFound)
}

// --- editor page -------------------------------------------------------------

func TestEditorPageRenders(t *testing.T) {
	h, dir, _ := stackDirHarness(t)
	cookie, _ := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(get(t, base+"/stacks/media/edit"), cookie, "", ""))
	requireStatus(t, rec, http.StatusOK)

	body := rec.Body.String()
	for _, want := range []string{
		"Media Server",
		`data-csrf-token="csrf-alice"`,
		`data-stack="media"`,
		"<textarea",
		"docker-compose.yml",
		".env",
		"/static/editor.js",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("editor page missing %q", want)
		}
	}
	// The host directory path must not leak into the HTML.
	if strings.Contains(body, dir) {
		t.Error("editor page leaks the host directory path")
	}
}

func TestEditorPagePermissionAndVisibility(t *testing.T) {
	h, _, _ := stackDirHarness(t)

	// bob has no "edit" permission.
	cookie, _ := h.sessionFor(t, "bob", []string{"family"})
	rec := h.do(withSession(get(t, base+"/stacks/media/edit"), cookie, "", ""))
	requireStatus(t, rec, http.StatusForbidden)

	// bob cannot see nextcloud at all.
	rec = h.do(withSession(get(t, base+"/stacks/nextcloud/edit"), cookie, "", ""))
	requireStatus(t, rec, http.StatusNotFound)

	// A stack without a directory is not editable even with permission.
	cookie, _ = h.sessionFor(t, "alice", []string{"admins"})
	rec = h.do(withSession(get(t, base+"/stacks/nextcloud/edit"), cookie, "", ""))
	requireStatus(t, rec, http.StatusNotFound)
}

func TestEditorPageRequiresSession(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	rec := h.do(get(t, base+"/stacks/media/edit"))
	requireStatus(t, rec, http.StatusFound)
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("redirect = %q, want /login", loc)
	}
}

// --- routes -------------------------------------------------------------------

func TestFileAPIWrongMethods(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})

	// POST on the files kind path: not an action route (three segments).
	rec := h.do(withSession(post(t, base+"/api/stacks/media/files/env", nil), cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusMethodNotAllowed)
	if allow := rec.Header().Get("Allow"); allow != "GET, PUT" {
		t.Errorf("Allow = %q", allow)
	}

	// DELETE likewise.
	req, _ := http.NewRequest(http.MethodDelete, base+"/api/stacks/media/files/env", nil)
	rec = h.do(withSession(req, cookie, csrf, "http://example.com"))
	requireStatus(t, rec, http.StatusMethodNotAllowed)
}

func TestAllowedActionsContainFileActionsWhenDirSet(t *testing.T) {
	h, _, _ := stackDirHarness(t)
	cookie, csrf := h.sessionFor(t, "alice", []string{"admins"})
	rec := h.do(withSession(get(t, base+"/api/stacks"), cookie, csrf, ""))
	requireStatus(t, rec, http.StatusOK)

	var resp stacksResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	media := resp.Stacks[0]
	want := "start stop restart pull up edit"
	if got := strings.Join(media.AllowedActions, " "); got != want {
		t.Errorf("allowed_actions = %q, want %q", got, want)
	}
}

// --- small helpers ------------------------------------------------------------

func recBody(resp *contentResponse) string {
	raw, _ := json.Marshal(resp)
	return string(raw)
}

func dir(h *harness) string {
	// Reaches into the holder for the test-visible stack directory.
	cfg := h.svc.Holder.Get()
	return cfg.Stacks[0].Dir
}
