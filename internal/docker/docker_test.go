package docker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestComposeArgBuilders(t *testing.T) {
	if got, want := composePSArgs("media"), []string{"compose", "-p", "media", "ps", "-a", "--format", "json"}; strings.Join(got, "\x1f") != strings.Join(want, "\x1f") {
		t.Errorf("composePSArgs = %v, want %v", got, want)
	}
	for action, want := range map[Action][]string{
		ActionStart:   {"compose", "-p", "nextcloud", "start"},
		ActionStop:    {"compose", "-p", "nextcloud", "stop"},
		ActionRestart: {"compose", "-p", "nextcloud", "restart"},
	} {
		if got := composeActionArgs("nextcloud", action); strings.Join(got, "\x1f") != strings.Join(want, "\x1f") {
			t.Errorf("composeActionArgs(%s) = %v, want %v", action, got, want)
		}
	}
}

func TestProjectNameGuard(t *testing.T) {
	// Hostile strings can never reach the CLI; config validation rejects them
	// at load time, this is the second line of defense.
	hostile := []string{
		"", "--format", "-p", "a b", "a;b", "$(id)", "`id`", "media;rm", "UPPER",
		"ä", "media\r\nfoo", "-x", string([]byte{0}),
	}
	ctx := context.Background()
	r := NewExecRunner("/bin/true", time.Second)
	for _, p := range hostile {
		if _, err := r.Status(ctx, p); err == nil {
			t.Errorf("Status(%q) accepted invalid project name", p)
		}
		if err := r.Do(ctx, p, ActionRestart); err == nil {
			t.Errorf("Do(%q) accepted invalid project name", p)
		}
	}
	// A clean name passes the guard (it will then run the (failing) binary).
	if _, err := r.Status(ctx, "media"); err != nil {
		if _, ok := err.(*CommandError); !ok {
			t.Errorf("Status(\"media\") failed before exec: %v", err)
		}
	}
}

func TestParseAction(t *testing.T) {
	for s, want := range map[string]Action{"start": ActionStart, "stop": ActionStop, "restart": ActionRestart} {
		got, ok := ParseAction(s)
		if !ok || got != want {
			t.Errorf("ParseAction(%q) = %v, %v; want %v, true", s, got, ok, want)
		}
	}
	for _, s := range []string{"", "START", "kill", "logs", "start ", "format"} {
		if _, ok := ParseAction(s); ok {
			t.Errorf("ParseAction(%q) unexpectedly accepted", s)
		}
	}
}

func TestDeriveState(t *testing.T) {
	tests := []struct {
		name     string
		services []Service
		want     string
	}{
		{"no services", nil, StateNotFound},
		{"all running", []Service{{"a", "running"}, {"b", "running"}}, StateRunning},
		{"all stopped", []Service{{"a", "exited"}, {"b", "created"}}, StateStopped},
		{"partial", []Service{{"a", "running"}, {"b", "exited"}}, StatePartial},
		{"paused counts as not running", []Service{{"a", "paused"}}, StateStopped},
	}
	for _, tc := range tests {
		if got := DeriveState(tc.services); got != tc.want {
			t.Errorf("DeriveState(%s) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestParseStatusFixtures(t *testing.T) {
	tests := []struct {
		file      string
		wantState string
		services  int
	}{
		{"ps-all-running.ndjson", StateRunning, 2},
		{"ps-all-stopped.ndjson", StateStopped, 2},
		{"ps-partial-running-one-stopped.ndjson", StatePartial, 2},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			st, err := ParseStatus(raw)
			if err != nil {
				t.Fatalf("ParseStatus() error = %v", err)
			}
			if st.State != tc.wantState {
				t.Errorf("State = %q, want %q", st.State, tc.wantState)
			}
			if len(st.Services) != tc.services {
				t.Errorf("services = %d, want %d", len(st.Services), tc.services)
			}
			if st.Services[0].Name != "probe1" {
				t.Errorf("service name = %q, want probe1", st.Services[0].Name)
			}
		})
	}
}

// psArrayFixture is the same recorded output wrapped in a JSON array — the
// format used by some Compose versions. The parser must accept both forms.
var psArrayFixture = []byte(`[
{"Name":"stackctl-probe-probe1-1","Service":"probe1","State":"running","Project":"stackctl-probe"},
{"Name":"stackctl-probe-probe2-1","Service":"probe2","State":"exited"}
]`)

func TestParseStatusArrayFormat(t *testing.T) {
	st, err := ParseStatus(psArrayFixture)
	if err != nil {
		t.Fatalf("ParseStatus() error = %v", err)
	}
	if st.State != StatePartial {
		t.Errorf("State = %q, want partial", st.State)
	}
	if len(st.Services) != 2 {
		t.Fatalf("services = %d, want 2", len(st.Services))
	}
	if st.Services[0].State != "running" || st.Services[1].State != "exited" {
		t.Errorf("per-service states = %v", st.Services)
	}
}

func TestParseStatusEmptyIsNotFound(t *testing.T) {
	for name, raw := range map[string][]byte{
		"empty":      {},
		"newline":    []byte("\n"),
		"whitespace": []byte("  \n\r\n  "),
		// Recorded behaviour of `docker compose -p unknown ps -a`:
		// exit 0 with no output means "project has no containers".
	} {
		st, err := ParseStatus(raw)
		if err != nil {
			t.Errorf("%s: ParseStatus() error = %v", name, err)
			continue
		}
		if st.State != StateNotFound {
			t.Errorf("%s: State = %q, want not_found", name, st.State)
		}
	}
}

func TestParseStatusGarbageIsUnknown(t *testing.T) {
	st, err := ParseStatus([]byte("this is not json\n"))
	if err == nil {
		t.Fatal("ParseStatus() accepted garbage")
	}
	if st.State != StateUnknown {
		t.Errorf("State = %q, want unknown", st.State)
	}
}

func TestParseStatusMissingServiceFallsBackToName(t *testing.T) {
	raw := []byte(`{"Name":"web-1","State":"running"}` + "\n")
	st, err := ParseStatus(raw)
	if err != nil {
		t.Fatal(err)
	}
	if st.Services[0].Name != "web-1" {
		t.Errorf("service name = %q, want web-1 (fallback to Name)", st.Services[0].Name)
	}
}

const fixtureNDJSON = `{"Name":"stackctl-probe-probe1-1","Service":"probe1","State":"running"}
{"Name":"stackctl-probe-probe2-1","Service":"probe2","State":"running"}
`

// fakeCompose writes an executable script that behaves like the compose CLI:
//   - when invoked with "ps" among its arguments it prints the fixture NDJSON;
//   - otherwise it succeeds.
//
// It appends its received environment to FAKECOMPOSE_ENVLOG so tests can
// assert on the minimal-environment guarantee.
func fakeCompose(t *testing.T) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "fake-docker")
	content := "#!/bin/sh\n" +
		"env > \"$FAKECOMPOSE_ENVLOG\"\n" +
		"for arg in \"$@\"; do\n" +
		"  if [ \"$arg\" = \"ps\" ]; then\n" +
		"    printf '%s' \"$FAKECOMPOSE_PS\"\n" +
		"    exit 0\n" +
		"  fi\n" +
		"done\n" +
		"exit 0\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

// runnerEnv is the ExecRunner env plus the variables the fake script needs.
func runnerEnv(t *testing.T) []string {
	t.Helper()
	return append(minimalEnv(),
		"FAKECOMPOSE_PS="+fixtureNDJSON,
		"FAKECOMPOSE_ENVLOG="+filepath.Join(t.TempDir(), "envlog"),
	)
}

func TestExecRunnerStatus(t *testing.T) {
	r := &ExecRunner{bin: fakeCompose(t), env: runnerEnv(t), timeout: time.Second}
	st, err := r.Status(context.Background(), "stackctl-probe")
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if st.State != StateRunning || len(st.Services) != 2 {
		t.Errorf("status = %+v, want running with 2 services", st)
	}
}

func TestExecRunnerMinimalEnv(t *testing.T) {
	t.Setenv("STACKCTL_MUST_NOT_PASS", "1") // test process env, not passed on
	env := runnerEnv(t)
	r := &ExecRunner{bin: fakeCompose(t), env: env, timeout: time.Second}
	if _, err := r.Status(context.Background(), "stackctl-probe"); err != nil {
		t.Fatal(err)
	}

	logPath := ""
	for _, kv := range env {
		if strings.HasPrefix(kv, "FAKECOMPOSE_ENVLOG=") {
			logPath = strings.TrimPrefix(kv, "FAKECOMPOSE_ENVLOG=")
		}
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("fake binary did not record its env: %v", err)
	}
	envlog := string(raw)
	if !strings.Contains(envlog, "PATH=") {
		t.Error("minimal env must contain PATH")
	}
	if strings.Contains(envlog, "STACKCTL_MUST_NOT_PASS") {
		t.Error("runner leaked test process environment into the child")
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "DOCKER_HOST=") {
			t.Errorf("DOCKER_HOST was set but not present in the process environment")
		}
	}
}

func TestExecRunnerUsesDockerHostWhenSet(t *testing.T) {
	t.Setenv("DOCKER_HOST", "unix:///tmp/opencode/fake-sock")
	r := &ExecRunner{bin: fakeCompose(t), env: runnerEnv(t), timeout: time.Second}
	if _, err := r.Status(context.Background(), "stackctl-probe"); err != nil {
		t.Fatal(err)
	}
	logPath := ""
	for _, kv := range r.env {
		if strings.HasPrefix(kv, "FAKECOMPOSE_ENVLOG=") {
			logPath = strings.TrimPrefix(kv, "FAKECOMPOSE_ENVLOG=")
		}
	}
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "DOCKER_HOST=unix:///tmp/opencode/fake-sock") {
		t.Error("DOCKER_HOST must be forwarded to the docker CLI")
	}
}

func TestExecRunnerCommandError(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fail-docker")
	content := "#!/bin/sh\necho 'no such project: stackctl-unknown' >&2\nexit 1\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &ExecRunner{bin: script, env: minimalEnv(), timeout: time.Second}
	err := r.Do(context.Background(), "stackctl-unknown", ActionStop)
	if err == nil {
		t.Fatal("Do() succeeded")
	}
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("Do() error = %T %v, want *CommandError", err, err)
	}
	if ce.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", ce.ExitCode)
	}
	if !strings.Contains(ce.Stderr, "no such project") {
		t.Errorf("Stderr = %q, want captured output", ce.Stderr)
	}
	// The error message itself must not leak stderr to clients.
	if strings.Contains(err.Error(), "no such project") {
		t.Errorf("Error() leaks stderr: %q", err.Error())
	}
}

func TestExecRunnerTimeout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "slow-docker")
	content := "#!/bin/sh\nsleep 5\n"
	if err := os.WriteFile(script, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &ExecRunner{bin: script, env: minimalEnv(), timeout: 150 * time.Millisecond}
	start := time.Now()
	err := r.Do(context.Background(), "slow", ActionStart)
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("Do() error = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("timeout took %v, command was not killed promptly", elapsed)
	}
}

func TestExecRunnerInvalidAction(t *testing.T) {
	r := &ExecRunner{bin: "/bin/false", env: minimalEnv(), timeout: time.Second}
	if err := r.Do(context.Background(), "media", Action("format")); err == nil {
		t.Error("Do() accepted unknown action")
	}
}
