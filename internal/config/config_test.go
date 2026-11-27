package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validConfig = `
server:
  listen: ":9090"
  external_url: "http://stacks.example.com"
  session_ttl: 8h
  session_hash_key: "{{HASH64}}"
  session_block_key: "{{BLOCK32}}"

oidc:
  issuer: "https://auth.example.com/realms/home"
  client_id: "stackctl"
  client_secret: "${STACKCTL_OIDC_SECRET}"
  scopes: ["openid", "profile", "email", "groups"]

docker:
  compose_binary: "docker"

stacks:
  - name: "media"
    label: "Media Server"
    project: "media"
  - name: "nextcloud"
    project: "nextcloud"

rules:
  - subjects:
      users: ["alice"]
      groups: ["admins"]
    stacks: ["*"]
    actions: ["start", "stop", "restart"]
  - subjects:
      groups: ["family"]
    stacks: ["media"]
    actions: ["restart"]
`

var (
	testHashKey64  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5A}, 64))
	testHashKey32  = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xA3}, 32))
	testBlockKey32 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
)

func TestParseValid(t *testing.T) {
	t.Setenv("STACKCTL_OIDC_SECRET", "s3cr3t")
	raw := strings.NewReplacer("{{HASH64}}", testHashKey64, "{{BLOCK32}}", testBlockKey32).Replace(validConfig)

	c, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	// Explicitly set values.
	if c.Server.Listen != ":9090" {
		t.Errorf("Listen = %q, want %q", c.Server.Listen, ":9090")
	}
	if c.Server.SessionTTL.Std() != 8*time.Hour {
		t.Errorf("SessionTTL = %v, want 8h", c.Server.SessionTTL.Std())
	}
	if c.OIDC.ClientSecret != "s3cr3t" {
		t.Errorf("env expansion failed, ClientSecret = %q", c.OIDC.ClientSecret)
	}

	// Defaults for absent fields.
	if c.Server.CommandTimeout.Std() != DefaultCommandTimeout {
		t.Errorf("CommandTimeout = %v, want default %v", c.Server.CommandTimeout.Std(), DefaultCommandTimeout)
	}
	if !c.Server.CookieSecure {
		t.Error("CookieSecure = false by default, want true")
	}
	if c.OIDC.UsernameClaim != DefaultUsernameClaim {
		t.Errorf("UsernameClaim = %q, want default", c.OIDC.UsernameClaim)
	}
	if c.OIDC.GroupsClaim != DefaultGroupsClaim {
		t.Errorf("GroupsClaim = %q, want default", c.OIDC.GroupsClaim)
	}
	if c.Docker.ComposeBinary != DefaultComposeBinary {
		t.Errorf("ComposeBinary = %q, want default", c.Docker.ComposeBinary)
	}

	// Label defaulting.
	if c.Stacks[1].Label != "nextcloud" {
		t.Errorf("Stacks[1].Label = %q, want derived from name", c.Stacks[1].Label)
	}

	// Decoded keys.
	if len(c.Server.HashKey) != 64 {
		t.Errorf("HashKey length = %d, want 64", len(c.Server.HashKey))
	}
	if len(c.Server.BlockKey) != 32 {
		t.Errorf("BlockKey length = %d, want 32", len(c.Server.BlockKey))
	}

	// Stack lookup helper.
	if _, ok := c.Stack("media"); !ok {
		t.Error("Stack(\"media\") not found")
	}
	if _, ok := c.Stack("nope"); ok {
		t.Error("Stack(\"nope\") unexpectedly found")
	}
}

func TestParseMinimalDefaultsScopes(t *testing.T) {
	raw := []byte(`
server:
  external_url: "https://stacks.example.com"
  session_hash_key: "` + testHashKey32 + `"
  session_block_key: "` + testBlockKey32 + `"
oidc:
  issuer: "https://auth.example.com"
  client_id: "stackctl"
  client_secret: "x"
`)
	c, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got, want := c.OIDC.Scopes, []string{"openid"}; len(got) != 1 || got[0] != want[0] {
		t.Errorf("Scopes = %v, want default %v", got, want)
	}
	if len(c.Stacks) != 0 {
		t.Errorf("Stacks = %v, want empty", c.Stacks)
	}
	if len(c.Rules) != 0 {
		t.Errorf("Rules = %v, want empty", c.Rules)
	}
}

// failureCase asserts a configuration is rejected and that the message hints
// at the expected cause.
type failureCase struct {
	name    string
	raw     string
	wantMsg string
}

func failureCases() []failureCase {
	base := `
server:
  external_url: "https://stacks.example.com"
  session_hash_key: "` + testHashKey32 + `"
  session_block_key: "` + testBlockKey32 + `"
oidc:
  issuer: "https://auth.example.com"
  client_id: "stackctl"
  client_secret: "x"
stacks:
  - name: "media"
    project: "media"
`
	variants := []failureCase{
		{"duplicate stack names", strings.Replace(base, `project: "media"`, "project: \"media\"\n  - name: \"media\"\n    project: \"other\"", 1), "duplicated"},
		{"bad stack name lowercase", strings.Replace(base, `name: "media"`, "name: \"Media\"", 1), "name"},
		{"stack name starts with dash", strings.Replace(base, `name: "media"`, "name: \"-media\"", 1), "name"},
		{"stack name too long", strings.Replace(base, `name: "media"`, "name: \""+strings.Repeat("a", 64)+"\"", 1), "name"},
		{"bad project name", strings.Replace(base, `project: "media"`, "project: \"Me dia\"", 1), "project"},
		{"rule unknown stack", base + "\nrules:\n  - {subjects: {users: [\"a\"]}, stacks: [\"ghost\"], actions: [\"restart\"]}\n", "unknown stack"},
		{"rule bad action", base + "\nrules:\n  - {subjects: {users: [\"a\"]}, stacks: [\"media\"], actions: [\"nuke\"]}\n", "must be one of"},
		{"rule empty actions", base + "\nrules:\n  - {subjects: {users: [\"a\"]}, stacks: [\"media\"], actions: []}\n", "actions"},
		{"rule empty stacks", base + "\nrules:\n  - {subjects: {users: [\"a\"]}, stacks: [], actions: [\"start\"]}\n", "stacks"},
		{"rule empty subjects", base + "\nrules:\n  - {subjects: {}, stacks: [\"media\"], actions: [\"start\"]}\n", "subjects"},
		{"missing external_url", strings.Replace(base, `external_url: "https://stacks.example.com"`, "", 1), "external_url"},
		{"external_url no host", strings.Replace(base, `"https://stacks.example.com"`, `"https:///"`, 1), "host"},
		{"external_url bad scheme", strings.Replace(base, `"https://stacks.example.com"`, `"ftp://stacks.example.com"`, 1), "http"},
		{"hash key bad base64", strings.Replace(base, testHashKey32, "not@base64!", 1), "base64"},
		{"hash key wrong length", strings.Replace(base, testHashKey32, base64.StdEncoding.EncodeToString(make([]byte, 16)), 1), "32 or 64 bytes"},
		{"block key wrong length", strings.Replace(base, testBlockKey32, base64.StdEncoding.EncodeToString(make([]byte, 31)), 1), "exactly 32 bytes"},
		{"missing issuer", strings.Replace(base, `issuer: "https://auth.example.com"`, "", 1), "issuer"},
		{"missing client_id", strings.Replace(base, `client_id: "stackctl"`, "", 1), "client_id"},
		{"missing client_secret", strings.Replace(base, `client_secret: "x"`, "", 1), "client_secret"},
		{"scopes without openid", strings.Replace(base, `client_secret: "x"`, "client_secret: \"x\"\n  scopes: [\"profile\"]", 1), "openid"},
		{"negative session ttl", strings.Replace(base, `external_url: "https://stacks.example.com"`, "external_url: \"https://stacks.example.com\"\n  session_ttl: -5m", 1), "positive"},
		{"zero command timeout", strings.Replace(base, `external_url: "https://stacks.example.com"`, "external_url: \"https://stacks.example.com\"\n  command_timeout: 0s", 1), "positive"},
		{"bad trusted proxy", strings.Replace(base, `external_url: "https://stacks.example.com"`, "external_url: \"https://stacks.example.com\"\n  trusted_proxies: [\"nope\"]", 1), "trusted_proxies"},
		{"unknown config key", strings.Replace(base, `external_url: "https://stacks.example.com"`, "external_url: \"https://stacks.example.com\"\n  unknown_server_key: true", 1), "not found in type"},
		{"unknown stack key typo", strings.Replace(base, `project: "media"`, "projekt: \"media\"", 1), "not found in type"},
		{"relative stack dir", strings.Replace(base, `project: "media"`, "project: \"media\"\n    dir: \"stacks/media\"", 1), "clean absolute path"},
		{"stack dir with dot traversal", strings.Replace(base, `project: "media"`, "project: \"media\"\n    dir: \"/stacks/../media\"", 1), "clean absolute path"},
		{"stack dir with backslash", strings.Replace(base, `project: "media"`, "project: \"media\"\n    dir: \"/stacks\\\\media\"", 1), "path separator"},
		{"compose_file without dir", strings.Replace(base, `project: "media"`, "project: \"media\"\n    compose_file: \"stack.yml\"", 1), "requires"},
		{"compose_file with path", strings.Replace(base, `project: "media"`, "project: \"media\"\n    dir: \"/s\"\n    compose_file: \"sub/stack.yml\"", 1), "plain file name"},
		{"compose_file dot name", strings.Replace(base, `project: "media"`, "project: \"media\"\n    dir: \"/s\"\n    compose_file: \"..hidden\"", 1), "plain file name"},
		{"zero pull timeout", base + "\ndocker:\n  pull_timeout: 0s\n", "pull_timeout"},
		{"negative pull timeout", base + "\ndocker:\n  pull_timeout: -3m\n", "pull_timeout"},
	}
	return variants
}

func TestParseFailures(t *testing.T) {
	for _, tc := range failureCases() {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.raw))
			if err == nil {
				t.Fatalf("Parse() accepted invalid config")
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("error = %q, want message containing %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

func TestExpandEnvUnsetVariable(t *testing.T) {
	raw := []byte(`oidc: {client_secret: "${STACKCTL_DEFINITELY_UNSET}"}`)
	_, err := Parse(raw)
	if err == nil {
		t.Fatal("Parse() accepted config with unset env reference")
	}
	if !strings.Contains(err.Error(), "STACKCTL_DEFINITELY_UNSET") {
		t.Errorf("error = %q, want it to name the missing variable", err.Error())
	}
}

func TestExpandEnvSetButEmptyAllowed(t *testing.T) {
	// An empty value is allowed through expansion; it then fails validation
	// downstream (empty client_secret) instead of being silently substituted.
	t.Setenv("STACKCTL_EMPTY_SECRET", "")
	raw := []byte(`
server:
  external_url: "https://stacks.example.com"
  session_hash_key: "` + testHashKey32 + `"
  session_block_key: "` + testBlockKey32 + `"
oidc:
  issuer: "https://auth.example.com"
  client_id: "stackctl"
  client_secret: "${STACKCTL_EMPTY_SECRET}"
`)
	_, err := Parse(raw)
	if err == nil || !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("Parse() error = %v, want client_secret required failure", err)
	}
}

func TestParseStackDirAndFileSettings(t *testing.T) {
	t.Setenv("STACKCTL_OIDC_SECRET", "s3cr3t")
	raw := strings.NewReplacer("{{HASH64}}", testHashKey64, "{{BLOCK32}}", testBlockKey32,
		`project: "media"`, "project: \"media\"\n    dir: \"/srv/stacks/media\"",
		`project: "nextcloud"`, "project: \"nextcloud\"\n    dir: \"/srv/stacks/nextcloud\"\n    compose_file: \"compose.yaml\"",
	).Replace(validConfig)

	c, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if c.Stacks[0].Dir != "/srv/stacks/media" || c.Stacks[0].ComposeFile != "" {
		t.Errorf("media stack = %+v", c.Stacks[0])
	}
	if c.Stacks[1].Dir != "/srv/stacks/nextcloud" || c.Stacks[1].ComposeFile != "compose.yaml" {
		t.Errorf("nextcloud stack = %+v", c.Stacks[1])
	}
	if c.Docker.PullTimeout.Std() != DefaultPullTimeout {
		t.Errorf("PullTimeout = %v, want default %v", c.Docker.PullTimeout.Std(), DefaultPullTimeout)
	}

	// New action names are accepted in rules.
	cfg := strings.NewReplacer(
		`actions: ["start", "stop", "restart"]`,
		`actions: ["start", "stop", "restart", "pull", "up", "update", "edit"]`,
	).Replace(raw)
	if _, err := Parse([]byte(cfg)); err != nil {
		t.Fatalf("Parse(new actions) error = %v", err)
	}
}

func TestActionHelpers(t *testing.T) {
	for _, a := range CanonicalActions {
		if !ValidAction(a) {
			t.Errorf("ValidAction(%q) = false", a)
		}
	}
	if len(CanonicalActions) != 7 {
		t.Errorf("CanonicalActions = %v, want 7 entries", CanonicalActions)
	}
	for _, a := range []string{"pull", "up", "update", "edit"} {
		if !ActionRequiresFiles(a) {
			t.Errorf("ActionRequiresFiles(%q) = false", a)
		}
	}
	for _, a := range []string{"start", "stop", "restart", "format", ""} {
		if ActionRequiresFiles(a) {
			t.Errorf("ActionRequiresFiles(%q) = true", a)
		}
	}
}

func TestDurationYAML(t *testing.T) {
	// Required preamble so validation failures do not mask duration errors.
	preamble := `
server:
  external_url: "https://stacks.example.com"
  session_ttl: "1h"
  session_hash_key: "` + testHashKey32 + `"
  session_block_key: "` + testBlockKey32 + `"
oidc:
  issuer: "https://auth.example.com"
  client_id: "stackctl"
  client_secret: "x"
`
	tests := []struct {
		name    string
		snippet string
		want    time.Duration
		wantErr bool
	}{
		{"string hours", `session_ttl: "8h"`, 8 * time.Hour, false},
		{"string seconds", `session_ttl: "120s"`, 120 * time.Second, false},
		{"string minutes", `session_ttl: "90m"`, 90 * time.Minute, false},
		{"bare integer nanoseconds", "session_ttl: 1500", 1500 * time.Nanosecond, false},
		{"no day unit", `session_ttl: "1d"`, 0, true},
		{"garbage", `session_ttl: "tomorrow"`, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// session_ttl is replaced inside the existing server: block
			// (a second server: key would be a duplicate-key parse error).
			raw := strings.Replace(preamble, `session_ttl: "1h"`, tc.snippet, 1)
			_, err := Parse([]byte(raw))
			if tc.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErr {
				c, _ := Parse([]byte(raw))
				if c.Server.SessionTTL.Std() != tc.want {
					t.Errorf("SessionTTL = %v, want %v", c.Server.SessionTTL.Std(), tc.want)
				}
			}
		})
	}
}

func TestHolderReloadKeepsOldConfigOnError(t *testing.T) {
	t.Setenv("STACKCTL_OIDC_SECRET", "s3cr3t")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	good := strings.NewReplacer("{{HASH64}}", testHashKey64, "{{BLOCK32}}", testBlockKey32).Replace(validConfig)
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}

	calls := 0
	holder, err := NewHolder(path)
	if err != nil {
		t.Fatalf("NewHolder() error = %v", err)
	}
	before := holder.Get()

	holder.OnChange(func(*Config) error {
		calls++
		return nil
	})

	// Invalid reload: keep the old config, report the error.
	bad := strings.Replace(good, `project: "media"`, `project: "Me dia"`, 1)
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := holder.Reload(); err == nil {
		t.Fatal("Reload() accepted invalid config")
	}
	if holder.Get() != before {
		t.Error("Reload() swapped config despite error")
	}
	if calls != 0 {
		t.Errorf("OnChange called %d times on failed reload, want 0", calls)
	}

	// Valid reload: swap and notify.
	updated := strings.Replace(good, `stacks: ["*"]`, `stacks: ["media"]`, 1)
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := holder.Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if calls != 1 {
		t.Errorf("OnChange called %d times, want 1", calls)
	}
	if holder.Get() == before {
		t.Error("Reload() did not swap config")
	}
	after := holder.Get()
	if len(after.Rules) == 0 || len(after.Rules[0].Stacks) != 1 || after.Rules[0].Stacks[0] != "media" {
		t.Errorf("reloaded rules = %+v, want narrowed stacks", after.Rules)
	}

	// The old snapshot must be unaffected by the swap.
	if len(before.Rules) == 0 || before.Rules[0].Stacks[0] != "*" {
		t.Errorf("previous snapshot mutated: %+v", before.Rules)
	}
}

func TestHolderSubscriberErrorReported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	t.Setenv("STACKCTL_OIDC_SECRET", "s3cr3t")
	if err := os.WriteFile(path, []byte(strings.NewReplacer("{{HASH64}}", testHashKey64, "{{BLOCK32}}", testBlockKey32).Replace(validConfig)), 0o600); err != nil {
		t.Fatal(err)
	}
	holder, err := NewHolder(path)
	if err != nil {
		t.Fatal(err)
	}
	holder.OnChange(func(*Config) error { return errTest })
	if err := holder.Reload(); err == nil || !strings.Contains(err.Error(), "errTest") {
		t.Errorf("Reload() error = %v, want subscriber error", err)
	}
}

func TestHolderStaticNoReload(t *testing.T) {
	h := NewStaticHolder(defaults())
	if err := h.Reload(); err == nil {
		t.Error("Reload() on static holder should fail")
	}
}

func TestExpandEnvMultilineAndMultiple(t *testing.T) {
	t.Setenv("STACKCTL_OIDC_SECRET", "a b c")
	raw := []byte("oidc:\n  issuer: \"${STACKCTL_OIDC_SECRET}\"\n")
	got, err := ExpandEnv(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "oidc:\n  issuer: \"a b c\"\n" {
		t.Errorf("ExpandEnv = %q", got)
	}
}

func TestParseTrustedProxy(t *testing.T) {
	for s, want := range map[string]string{
		"10.0.0.1":   "10.0.0.1/32",
		"10.0.0.0/8": "10.0.0.0/8",
		"::1":        "::1/128",
		"fd00::/64":  "fd00::/64",
	} {
		n, err := parseTrustedProxy(s)
		if err != nil {
			t.Errorf("parseTrustedProxy(%q) error = %v", s, err)
			continue
		}
		if got := n.String(); got != want {
			t.Errorf("parseTrustedProxy(%q) = %q, want %q", s, got, want)
		}
	}
	for _, bad := range []string{"not-ip", "10.0.0.0/99", ""} {
		if _, err := parseTrustedProxy(bad); err == nil {
			t.Errorf("parseTrustedProxy(%q) accepted invalid input", bad)
		}
	}
}

var errTest = errTestError{}

type errTestError struct{}

func (errTestError) Error() string { return "errTest" }
