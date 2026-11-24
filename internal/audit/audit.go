// Package audit emits one structured log line per security-relevant event
// (stack actions, logins, logouts, config reloads) on stdout via slog.
package audit

import (
	"log/slog"
	"time"
)

// Logger writes audit events. It never logs secrets such as tokens, cookies
// or the OIDC client secret.
type Logger struct {
	slog *slog.Logger
}

// New wraps the application logger.
func New(l *slog.Logger) *Logger {
	return &Logger{slog: l}
}

// StackAction records one stack action attempt with its final result. result
// is one of "ok", "denied", "conflict", "timeout", "error"; reason may be
// empty or explain a denial ("no_permission", "unknown_or_invisible",
// "in_progress"). groups is nil for users without group claims; it is logged
// as an empty JSON array, never omitted, to keep lines comparable.
func (a *Logger) StackAction(user string, groups []string, stack, project, action, result, reason, remoteIP string, duration time.Duration) {
	args := []any{
		"user", user,
		"groups", groups,
		"stack", stack,
		"project", project,
		"action", action,
		"result", result,
		"duration_ms", duration.Milliseconds(),
		"remote_ip", remoteIP,
	}
	if groups == nil {
		// Render consistently as [] instead of null in the JSON log line
		// (args[3] is the groups value, args[2] its key).
		args[3] = []string{}
	}
	if reason != "" {
		args = append(args, "reason", reason)
	}
	a.slog.Info("stack_action", args...)
}

// Login records a successful or failed login attempt. detail carries a short
// sanitized cause on failure.
func (a *Logger) Login(user string, success bool, remoteIP, detail string) {
	args := []any{"user", user, "success", success, "remote_ip", remoteIP}
	if detail != "" {
		args = append(args, "detail", detail)
	}
	a.slog.Info("login", args...)
}

// Logout records a logout attempt (success or missing session).
func (a *Logger) Logout(user string, success bool, remoteIP string) {
	a.slog.Info("logout", "user", user, "success", success, "remote_ip", remoteIP)
}

// Denied records an authentication/authorization rejection that is not tied
// to a specific stack action (e.g. CSRF or Origin failure, logout without a
// session). Stack-endpoint denials are additionally recorded by
// StackAction with result "denied".
func (a *Logger) Denied(user, path, remoteIP, reason string) {
	a.slog.Info("request_denied", "user", user, "path", path, "remote_ip", remoteIP, "reason", reason)
}

// ConfigReload records the outcome of a SIGHUP configuration reload.
func (a *Logger) ConfigReload(success bool, path string, err error) {
	args := []any{"success", success, "path", path}
	if err != nil {
		args = append(args, "error", err.Error())
	}
	a.slog.Info("config_reload", args...)
}
