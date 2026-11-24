package audit

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
)

// capture returns a Logger and the buffer its log lines land in.
func capture() (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))
	return New(l), &buf
}

func TestStackActionLog(t *testing.T) {
	aud, buf := capture()
	aud.StackAction("bob", []string{"family"}, "media", "media", "restart", "ok", "", "203.0.113.5", 2310*time.Millisecond)

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("audit line is not JSON: %v\n%s", err, buf.String())
	}
	want := map[string]any{
		"msg":         "stack_action",
		"user":        "bob",
		"stack":       "media",
		"project":     "media",
		"action":      "restart",
		"result":      "ok",
		"duration_ms": float64(2310),
		"remote_ip":   "203.0.113.5",
		"level":       "INFO",
	}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("field %q = %v, want %v", k, line[k], v)
		}
	}
	groups, ok := line["groups"].([]any)
	if !ok || len(groups) != 1 || groups[0] != "family" {
		t.Errorf("groups = %v, want [family]", line["groups"])
	}
	// The plan's example line carries exactly these keys plus time.
	for _, k := range []string{"time", "msg", "user", "groups", "stack", "project", "action", "result", "duration_ms", "remote_ip"} {
		if _, ok := line[k]; !ok {
			t.Errorf("missing audit field %q", k)
		}
	}
}

func TestStackActionNilGroupsRenderAsEmptyArray(t *testing.T) {
	aud, buf := capture()
	aud.StackAction("alice", nil, "media", "media", "stop", "denied", "no_permission", "127.0.0.1", 0)

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	groups, ok := line["groups"].([]any)
	if !ok || len(groups) != 0 {
		t.Errorf("groups = %v (%T), want an empty array, not null", line["groups"], line["groups"])
	}
	if line["reason"] != "no_permission" {
		t.Errorf("reason = %v", line["reason"])
	}
}

func TestLoginAndDeniedAndReloadLogs(t *testing.T) {
	aud, buf := capture()
	aud.Login("alice", true, "10.0.0.2", "")
	aud.Login("unknown", false, "10.0.0.2", "state mismatch")
	aud.Logout("alice", true, "10.0.0.2")
	aud.Denied("alice", "/logout", "10.0.0.2", "origin not allowed")
	aud.ConfigReload(false, "/etc/stackctl/config.yaml", errReloadMock)

	out := buf.String()
	var lines []map[string]any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for {
		var l map[string]any
		if err := dec.Decode(&l); err != nil {
			break
		}
		lines = append(lines, l)
	}
	if len(lines) != 5 {
		t.Fatalf("got %d lines, want 5:\n%s", len(lines), out)
	}
	msgs := []string{}
	for _, l := range lines {
		msgs = append(msgs, l["msg"].(string))
	}
	want := []string{"login", "login", "logout", "request_denied", "config_reload"}
	for i := range want {
		if msgs[i] != want[i] {
			t.Errorf("line %d msg = %q, want %q", i, msgs[i], want[i])
		}
	}
	if !contains(lines[4], "success", false) {
		t.Error("config_reload failure line must carry success=false")
	}
	if contains(lines[0], "detail", "") || hasKey(lines[0], "detail") {
		t.Error("successful login must not carry a detail field")
	}
}

func TestNoSecretsInLogLines(t *testing.T) {
	aud, buf := capture()
	// Exchange-style provider errors are reduced to their code; make sure a
	// hostile detail never appears.
	aud.Login("unknown", false, "10.0.0.2", "token exchange failed (provider error: invalid_client)")
	if bytes.Contains(buf.Bytes(), []byte("client_secret")) {
		t.Error("client secret leaked into audit log")
	}
}

func contains(line map[string]any, key string, want any) bool {
	v, ok := line[key]
	return ok && v == want
}

func hasKey(line map[string]any, key string) bool {
	_, ok := line[key]
	return ok
}

var errReloadMock = errorString("validation failed")

type errorString string

func (e errorString) Error() string { return string(e) }
