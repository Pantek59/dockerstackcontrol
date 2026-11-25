// Package config defines, loads, validates and hot-reloads stackctl's YAML
// configuration.
//
// The configuration is the single source of authorization truth: it declares
// the manageable stacks and the permission rules. Values referenced as
// ${ENV_NAME} are expanded from the process environment before parsing.
// Unknown keys are rejected so that typos cannot silently disable a rule.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultConfigPath is used when STACKCTL_CONFIG is unset and no -config flag
// is given.
const DefaultConfigPath = "/etc/stackctl/config.yaml"

// Defaults applied to fields that are absent from the configuration file.
const (
	DefaultListen         = ":8080"
	DefaultSessionTTL     = 12 * time.Hour
	DefaultCommandTimeout = 120 * time.Second
	DefaultPullTimeout    = 10 * time.Minute
	DefaultComposeBinary  = "docker"
	DefaultUsernameClaim  = "preferred_username"
	DefaultGroupsClaim    = "groups"
)

// Action names as used in rule declarations.
//
// start/stop/restart operate on the existing containers of a project and
// never need a compose file. pull/up recreate from a compose model and edit
// touches the stack files, so all three require the stack to declare "dir".
const (
	ActionStart   = "start"
	ActionStop    = "stop"
	ActionRestart = "restart"
	ActionPull    = "pull"
	ActionUp      = "up"
	ActionEdit    = "edit"
)

// ActionRequiresFiles reports whether an action needs the stack's compose
// model on disk (config.Stack.Dir).
func ActionRequiresFiles(action string) bool {
	return action == ActionPull || action == ActionUp || action == ActionEdit
}

// CanonicalActions is the canonical, deterministic order used wherever a list
// of a user's allowed actions is rendered or compared.
var CanonicalActions = []string{ActionStart, ActionStop, ActionRestart, ActionPull, ActionUp, ActionEdit}

// ValidAction reports whether s is one of the known action names.
func ValidAction(s string) bool {
	switch s {
	case ActionStart, ActionStop, ActionRestart, ActionPull, ActionUp, ActionEdit:
		return true
	}
	return false
}

var (
	validStackNameRegexp   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	validProjectNameRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	envReferenceRegexp     = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
	// A compose file override is joined to the stack directory; it must be a
	// single plain file name so it can never point outside that directory.
	validComposeFileRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// ValidStackName reports whether name matches the required stack name syntax
// ^[a-z0-9][a-z0-9_-]{0,62}$.
func ValidStackName(name string) bool { return validStackNameRegexp.MatchString(name) }

// ValidProjectName reports whether name matches Compose's project name syntax
// ^[a-z0-9][a-z0-9_-]*$. Validated here so no user-controlled string can ever
// reach a docker command line.
func ValidProjectName(name string) bool { return validProjectNameRegexp.MatchString(name) }

// Config is the complete application configuration. A *Config handed out by a
// Holder must be treated as immutable: it may be swapped by a reload at any
// time and is shared across concurrent requests.
type Config struct {
	Server Server  `yaml:"server"`
	OIDC   OIDC    `yaml:"oidc"`
	Docker Docker  `yaml:"docker"`
	Stacks []Stack `yaml:"stacks"`
	Rules  []Rule  `yaml:"rules"`
}

// Stack returns the stack with the given name.
func (c *Config) Stack(name string) (Stack, bool) {
	for _, s := range c.Stacks {
		if s.Name == name {
			return s, true
		}
	}
	return Stack{}, false
}

// Server holds HTTP server, cookie, timeout and proxy settings.
type Server struct {
	Listen          string   `yaml:"listen"`
	ExternalURL     string   `yaml:"external_url"`
	CookieSecure    bool     `yaml:"cookie_secure"`
	SessionTTL      Duration `yaml:"session_ttl"`
	SessionHashKey  string   `yaml:"session_hash_key"`
	SessionBlockKey string   `yaml:"session_block_key"`
	CommandTimeout  Duration `yaml:"command_timeout"`
	TrustedProxies  []string `yaml:"trusted_proxies"`

	// Decoded values, filled in by Validate; never populated from YAML
	// directly (they have no yaml tags under the names below).
	HashKey          []byte       `yaml:"-"`
	BlockKey         []byte       `yaml:"-"`
	TrustedProxyNets []*net.IPNet `yaml:"-"`

	// Note: yaml:"-" keeps the decoded fields out of the mapping. yaml.v3
	// honours "-" by skipping the field on both encode and decode.
}

// OIDC configures the OpenID Connect identity provider.
type OIDC struct {
	Issuer        string   `yaml:"issuer"`
	ClientID      string   `yaml:"client_id"`
	ClientSecret  string   `yaml:"client_secret"`
	Scopes        []string `yaml:"scopes"`
	UsernameClaim string   `yaml:"username_claim"`
	GroupsClaim   string   `yaml:"groups_claim"`
	RequiredGroup string   `yaml:"required_group"`
}

// Docker configures how docker compose is invoked.
type Docker struct {
	ComposeBinary string `yaml:"compose_binary"`
	// PullTimeout bounds the file-backed commands pull and up -d, which
	// download and thereby outlast interactive actions such as restart.
	PullTimeout Duration `yaml:"pull_timeout"`
}

// Stack is one manageable Compose project. Name is the stable identifier used
// in URLs and rules; Project is the Compose project name and is never taken
// from user input.
//
// Dir optionally points at the directory on the Docker host that holds the
// stack's compose model ("docker-compose.yml" and ".env"). It enables the
// file-backed actions pull, up and edit. When it is unset the stack remains
// label-based: only start/stop/restart work (docker compose cannot pull or
// up a project without its file). ComposeFile overrides the detected main
// compose file inside Dir.
type Stack struct {
	Name        string `yaml:"name"`
	Label       string `yaml:"label"`
	Project     string `yaml:"project"`
	Dir         string `yaml:"dir"`
	ComposeFile string `yaml:"compose_file"`
}

// Rule grants actions on stacks to subjects. Matching rules are unioned.
type Rule struct {
	Subjects SubjectSet `yaml:"subjects"`
	Stacks   []string   `yaml:"stacks"`
	Actions  []string   `yaml:"actions"`
}

// SubjectSet lists the users and groups a rule applies to.
type SubjectSet struct {
	Users  []string `yaml:"users"`
	Groups []string `yaml:"groups"`
}

// Duration wraps time.Duration so it can be written in YAML as a string such
// as "12h" or "120s". A bare integer means nanoseconds.
type Duration time.Duration

// Std returns the wrapped time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// UnmarshalYAML implements yaml.v3 unmarshalling for Duration.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar value")
	}
	if dur, err := time.ParseDuration(strings.TrimSpace(node.Value)); err == nil {
		*d = Duration(dur)
		return nil
	}
	var nanos int64
	if err := node.Decode(&nanos); err == nil {
		*d = Duration(nanos)
		return nil
	}
	return fmt.Errorf("invalid duration %q (want e.g. \"30s\", \"5m\" or an integer of nanoseconds)", node.Value)
}

// MarshalYAML implements yaml.v3 marshalling for Duration.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

func defaults() *Config {
	return &Config{
		Server: Server{
			Listen:         DefaultListen,
			CookieSecure:   true,
			SessionTTL:     Duration(DefaultSessionTTL),
			CommandTimeout: Duration(DefaultCommandTimeout),
		},
		OIDC: OIDC{
			UsernameClaim: DefaultUsernameClaim,
			GroupsClaim:   DefaultGroupsClaim,
		},
		Docker: Docker{
			ComposeBinary: DefaultComposeBinary,
			PullTimeout:   Duration(DefaultPullTimeout),
		},
	}
}

// Load reads and parses the configuration file at path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse expands environment references, applies defaults, unmarshals and
// validates the configuration.
func Parse(raw []byte) (*Config, error) {
	expanded, err := ExpandEnv(raw)
	if err != nil {
		return nil, err
	}

	c := defaults()
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true) // reject unknown keys: typos must not silently disable rules
	if err := dec.Decode(c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// ExpandEnv replaces every ${NAME} reference in raw with the value of the
// environment variable NAME. Referencing an unset variable is an error so
// that a missing secret never silently becomes an empty string.
func ExpandEnv(raw []byte) ([]byte, error) {
	var missing []string
	out := envReferenceRegexp.ReplaceAllStringFunc(string(raw), func(ref string) string {
		name := ref[2 : len(ref)-1]
		val, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return ref
		}
		return val
	})
	if len(missing) > 0 {
		slices.Sort(missing)
		missing = slices.Compact(missing)
		return nil, fmt.Errorf("config references unset environment variables: %s", strings.Join(missing, ", "))
	}
	return []byte(out), nil
}

// Validate checks the configuration and normalizes a few fields in place
// (default scopes, default label, trimmed external URL, decoded keys).
// It returns a joined error listing every problem found.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	// --- server ---
	c.Server.ExternalURL = strings.TrimRight(strings.TrimSpace(c.Server.ExternalURL), "/")
	if c.Server.ExternalURL == "" {
		fail("server.external_url is required")
	} else if u, err := url.Parse(c.Server.ExternalURL); err != nil {
		fail("server.external_url: %v", err)
	} else {
		if u.Scheme != "http" && u.Scheme != "https" {
			fail("server.external_url must start with http:// or https://")
		}
		if u.Host == "" {
			fail("server.external_url must contain a host")
		}
		if u.RawQuery != "" || u.Fragment != "" {
			fail("server.external_url must not contain a query or fragment")
		}
	}
	if c.Server.Listen == "" {
		fail("server.listen must not be empty")
	}
	if c.Server.SessionTTL <= 0 {
		fail("server.session_ttl must be positive")
	}
	if c.Server.CommandTimeout <= 0 {
		fail("server.command_timeout must be positive")
	}

	hk, err := decodeKey(c.Server.SessionHashKey)
	switch {
	case err != nil:
		fail("server.session_hash_key: %v", err)
	case len(hk) != 32 && len(hk) != 64:
		fail("server.session_hash_key must decode to 32 or 64 bytes, got %d", len(hk))
	default:
		c.Server.HashKey = hk
	}
	bk, err := decodeKey(c.Server.SessionBlockKey)
	switch {
	case err != nil:
		fail("server.session_block_key: %v", err)
	case len(bk) != 32:
		fail("server.session_block_key must decode to exactly 32 bytes, got %d", len(bk))
	default:
		c.Server.BlockKey = bk
	}

	c.Server.TrustedProxyNets = nil
	for i, entry := range c.Server.TrustedProxies {
		ipnet, err := parseTrustedProxy(entry)
		if err != nil {
			fail("server.trusted_proxies[%d]: %v", i, err)
			continue
		}
		c.Server.TrustedProxyNets = append(c.Server.TrustedProxyNets, ipnet)
	}

	// --- oidc ---
	if u, err := url.Parse(c.OIDC.Issuer); err != nil || u.Scheme == "" || u.Host == "" {
		fail("oidc.issuer must be an absolute URL")
	} else if u.Scheme != "http" && u.Scheme != "https" {
		fail("oidc.issuer must start with http:// or https://")
	}
	if c.OIDC.ClientID == "" {
		fail("oidc.client_id is required")
	}
	if c.OIDC.ClientSecret == "" {
		fail("oidc.client_secret is required")
	}
	if len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = []string{"openid"}
	}
	if !slices.Contains(c.OIDC.Scopes, "openid") {
		fail("oidc.scopes must contain \"openid\"")
	}
	if c.OIDC.UsernameClaim == "" {
		fail("oidc.username_claim must not be empty")
	}
	if c.OIDC.GroupsClaim == "" {
		fail("oidc.groups_claim must not be empty")
	}

	// --- docker ---
	if c.Docker.ComposeBinary == "" {
		fail("docker.compose_binary must not be empty")
	}
	if c.Docker.PullTimeout <= 0 {
		fail("docker.pull_timeout must be positive")
	}

	// --- stacks ---
	seen := make(map[string]bool, len(c.Stacks))
	for i, s := range c.Stacks {
		if !validStackNameRegexp.MatchString(s.Name) {
			fail("stacks[%d].name %q must match ^[a-z0-9][a-z0-9_-]{0,62}$", i, s.Name)
		}
		if seen[s.Name] {
			fail("stacks[%d].name %q is duplicated", i, s.Name)
		}
		seen[s.Name] = true
		if !validProjectNameRegexp.MatchString(s.Project) {
			fail("stacks[%d].project %q must match ^[a-z0-9][a-z0-9_-]*$", i, s.Project)
		}
		if s.Label == "" {
			c.Stacks[i].Label = s.Name
		}
		// Dir is optional, but if declared it must be a safe absolute path:
		// it is joined — never traversed — when files are addressed, and it
		// is passed to the compose CLI as part of -f <dir>/<file>.
		if s.Dir != "" {
			cleaned := filepath.Clean(s.Dir)
			if !filepath.IsAbs(cleaned) || cleaned != s.Dir {
				fail("stacks[%d].dir %q must be a clean absolute path", i, s.Dir)
			}
			if strings.ContainsRune(cleaned, '\\') {
				fail("stacks[%d].dir %q must use / as path separator", i, s.Dir)
			}
			c.Stacks[i].Dir = cleaned
		}
		// ComposeFile, when overridden, is joined to Dir; it must stay a
		// single file name so it cannot point anywhere else in the tree.
		if s.ComposeFile != "" {
			if s.Dir == "" {
				fail("stacks[%d].compose_file %q requires stacks[%d].dir to be set", i, s.ComposeFile, i)
			}
			if !validComposeFileRegexp.MatchString(s.ComposeFile) {
				fail("stacks[%d].compose_file %q must be a plain file name", i, s.ComposeFile)
			}
		}
	}

	// --- rules ---
	for i, r := range c.Rules {
		if len(r.Actions) == 0 {
			fail("rules[%d].actions must not be empty", i)
		}
		for _, a := range r.Actions {
			if !ValidAction(a) {
				fail("rules[%d].action %q must be one of %q", i, a, strings.Join(CanonicalActions, ", "))
			}
		}
		if len(r.Stacks) == 0 {
			fail("rules[%d].stacks must not be empty", i)
		}
		for _, sn := range r.Stacks {
			if sn == "*" {
				continue
			}
			if !seen[sn] {
				fail("rules[%d] references unknown stack %q", i, sn)
			}
		}
		if len(r.Subjects.Users) == 0 && len(r.Subjects.Groups) == 0 {
			fail("rules[%d].subjects must list at least one user or group", i)
		}
	}

	return errors.Join(errs...)
}

// decodeKey decodes a base64 (standard or raw/unpadded) key from config text.
func decodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("is required")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("is not valid base64: %w", err)
	}
	return b, nil
}

// parseTrustedProxy parses one trusted proxy entry, either a CIDR such as
// 10.0.0.0/8 or a bare IP address (treated as a /32 or /128).
func parseTrustedProxy(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("%q is not an IP address or CIDR", s)
		}
		if ip.To4() != nil {
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("%q is not a valid CIDR", s)
	}
	return ipnet, nil
}
