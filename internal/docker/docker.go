// Package docker runs docker compose commands for whole Compose projects and
// derives a stack status from their output.
//
// Security-relevant properties:
//   - Commands are built as a fixed argument list and executed with
//     [exec.CommandContext]; no shell is involved and no user input is ever
//     interpolated. The project name must match the same validation regex as
//     the configuration loader (defense in depth: validated twice).
//   - The action is a fixed enum, never a raw string from a request.
//   - Every command runs under a context timeout; stdout and stderr are
//     captured separately and never returned to clients (only to the caller
//     for server-side logging).
package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Action is one of the state-changing operations on a compose project.
type Action string

const (
	ActionStart   Action = "start"
	ActionStop    Action = "stop"
	ActionRestart Action = "restart"
	ActionPull    Action = "pull"
	ActionUp      Action = "up"
	ActionUpdate  Action = "update"
)

// ParseAction converts a request string into an Action. Unknown strings are
// rejected: they can never reach an argument list.
func ParseAction(s string) (Action, bool) {
	switch Action(s) {
	case ActionStart, ActionStop, ActionRestart, ActionPull, ActionUp, ActionUpdate:
		return Action(s), true
	default:
		return "", false
	}
}

// requiresFile reports whether the action drives compose through a compose
// model (pull, up, update) instead of the project's existing containers.
func (a Action) requiresFile() bool {
	return a == ActionPull || a == ActionUp || a == ActionUpdate
}

// Stack status derived from the services of a compose project.
const (
	StateRunning   = "running"
	StateStopped   = "stopped"
	StatePartial   = "partial"
	StateNotFound  = "not_found"
	StateUnknown   = "unknown"
	ServiceRunning = "running"
)

// Service is one compose service with its container state.
type Service struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// StackStatus is the aggregated status of a whole project.
type StackStatus struct {
	State    string    `json:"state"`
	Services []Service `json:"services"`
}

// ErrTimeout is returned when a docker command exceeds the configured timeout.
var ErrTimeout = errors.New("docker compose command timed out")

// CommandError carries details of a non-timeout docker command failure. The
// Stderr field must only be used for server-side logging, never returned to
// clients.
type CommandError struct {
	Command  string
	ExitCode int
	Stderr   string
}

func (e *CommandError) Error() string {
	// Deliberately excludes Stderr: command output never leaves the server.
	return fmt.Sprintf("docker compose command failed (command: %q, exit code: %d)", e.Command, e.ExitCode)
}

// Runner executes actions and status queries against the local Docker daemon.
type Runner interface {
	// Status reports the current state of the compose project. It returns
	// StateNotFound with a nil error when the project has no containers.
	Status(ctx context.Context, project string) (StackStatus, error)
	// Do performs the given action and returns once the command(s) finished.
	// For the label-based actions (start, stop, restart) only spec.Project is
	// used. The file-backed actions (pull, up, update) additionally require
	// spec.Dir (absolute stack directory) and spec.Compose (main compose
	// file name inside it). update runs pull and then up -d, best effort; a
	// pull-only failure comes back as *UpdateError with a nil UpErr.
	Do(ctx context.Context, spec StackSpec, action Action) error
	// Validate loads the compose model described by spec without touching
	// the daemon (compose config --quiet): used to check an edited compose
	// file before it replaces the current one.
	Validate(ctx context.Context, spec StackSpec) error
}

// StackSpec addresses one compose project. Project is always required. Dir
// and Compose are the stack directory (absolute, as configured) and the main
// compose file's plain file name inside it; they are needed only by the
// file-backed actions and by Validate.
type StackSpec struct {
	Project string
	Dir     string
	Compose string
}

// projectRegexp mirrors internal/config.ValidProjectName. It is duplicated
// here so the executor refuses to pass any string through to the CLI even if
// a caller bypassed config validation.
var projectRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// validFileNameRegexp mirrors internal/config's compose_file validation: a
// single plain file name that is joined to the validated stack directory.
var validFileNameRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// ExecRunner invokes the docker CLI (or another compose-providing binary) in
// the form: <binary> compose -p <project> <subcommand>, or
// <binary> compose -p <project> -f <file> <subcommand> for file-backed
// commands.
type ExecRunner struct {
	bin     string
	env     []string
	timeout time.Duration
	// pullTimeout bounds the commands that download images (pull, up);
	// falls back to timeout when zero (tests construct the struct directly).
	pullTimeout time.Duration
}

// NewExecRunner builds a runner. bin is the compose-providing binary (usually
// "docker"); timeout bounds every single command and pullTimeout bounds the
// slower commands that download images. Pass pullTimeout <= 0 to share
// timeout.
func NewExecRunner(bin string, timeout, pullTimeout time.Duration) *ExecRunner {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	if pullTimeout <= 0 {
		pullTimeout = timeout
	}
	return &ExecRunner{
		bin:         bin,
		env:         minimalEnv(),
		timeout:     timeout,
		pullTimeout: pullTimeout,
	}
}

// minimalEnv keeps PATH, HOME and DOCKER_HOST (when set) so the compose CLI
// can find the daemon and its own config, and nothing else.
func minimalEnv() []string {
	var env []string
	for _, name := range []string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG"} {
		if v, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}

// composePSArgs returns the exact argument list for a status query.
func composePSArgs(project string) []string {
	return []string{"compose", "-p", project, "ps", "-a", "--format", "json"}
}

// composeActionArgs returns the exact argument list for a label-based action
// (operating on the project's existing containers).
func composeActionArgs(project string, action Action) []string {
	return []string{"compose", "-p", project, string(action)}
}

// composeFileActionArgs returns the exact argument list for a file-backed
// action (pull, up). The compose model is pinned with -f so that it resolves
// identically regardless of the working directory; compose then reads the
// .env file from the model's directory. up stays in the background (-d):
// the handler answers after the command, not after a foreground run.
func composeFileActionArgs(project, composeFile string, action Action) []string {
	args := []string{"compose", "-p", project, "-f", composeFile, string(action)}
	if action == ActionUp {
		args = append(args, "-d")
	}
	return args
}

// composeConfigArgs validates a compose model without touching the daemon.
func composeConfigArgs(project, composeFile string) []string {
	return []string{"compose", "-p", project, "-f", composeFile, "config", "--quiet"}
}

// Status implements Runner.
func (r *ExecRunner) Status(ctx context.Context, project string) (StackStatus, error) {
	if err := validProject(project); err != nil {
		return StackStatus{State: StateUnknown}, err
	}
	stdout, _, err := r.run(ctx, composePSArgs(project), r.timeout)
	if err != nil {
		return StackStatus{State: StateUnknown}, err
	}
	return ParseStatus(stdout)
}

// Do implements Runner.
func (r *ExecRunner) Do(ctx context.Context, spec StackSpec, action Action) error {
	if err := validProject(spec.Project); err != nil {
		return err
	}
	if !action.requiresFile() {
		switch action {
		case ActionStart, ActionStop, ActionRestart:
		default:
			return fmt.Errorf("invalid action %q", action)
		}
		_, _, err := r.run(ctx, composeActionArgs(spec.Project, action), r.timeout)
		return err
	}
	file, err := r.composeFilePath(spec)
	if err != nil {
		return err
	}
	if action == ActionUpdate {
		return r.update(ctx, spec.Project, file)
	}
	if _, _, err := r.run(ctx, composeFileActionArgs(spec.Project, file, action), r.pullTimeout); err != nil {
		return err
	}
	return nil
}

// UpdateError carries the outcome of an update (pull, then up -d, best
// effort). At least one field is non-nil when it is returned. Error()
// deliberately never contains command output — the same guarantee as
// [CommandError] — so this text is safe to include in API responses; stderr
// stays server-side.
type UpdateError struct {
	// PullErr is non-nil when the image pull failed or timed out.
	PullErr error
	// UpErr is non-nil when the container recreation failed or timed out.
	UpErr error
}

func (e *UpdateError) Error() string {
	var parts []string
	if e.PullErr != nil {
		parts = append(parts, "image pull failed: "+e.PullErr.Error())
	}
	if e.UpErr != nil {
		parts = append(parts, "container recreation failed: "+e.UpErr.Error())
	}
	return strings.Join(parts, "; ")
}

// Unwrap yields the failing step errors (up first) so errors.Is finds
// ErrTimeout through the chain.
func (e *UpdateError) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.UpErr != nil {
		out = append(out, e.UpErr)
	}
	if e.PullErr != nil {
		out = append(out, e.PullErr)
	}
	return out
}

// update runs the two-step "newest images, then recreate" sequence, best
// effort: a failed pull must not block the recreation, because the images
// that did arrive — or were already local — remain the newest applicable
// ones, and compose recreates only what the model changed. Whichever steps
// failed are reported in the returned *UpdateError; the caller decides
// whether a pull-only failure is an overall failure. Each step is bounded by
// its own pullTimeout.
func (r *ExecRunner) update(ctx context.Context, project, composeFile string) error {
	ue := &UpdateError{}
	if _, _, err := r.run(ctx, composeFileActionArgs(project, composeFile, ActionPull), r.pullTimeout); err != nil {
		ue.PullErr = err
	}
	if _, _, err := r.run(ctx, composeFileActionArgs(project, composeFile, ActionUp), r.pullTimeout); err != nil {
		ue.UpErr = err
	}
	if ue.PullErr == nil && ue.UpErr == nil {
		return nil
	}
	return ue
}

// Validate implements Runner. It runs compose config --quiet, which parses
// and schema-checks the model client-side without talking to the daemon.
func (r *ExecRunner) Validate(ctx context.Context, spec StackSpec) error {
	if err := validProject(spec.Project); err != nil {
		return err
	}
	file, err := r.composeFilePath(spec)
	if err != nil {
		return err
	}
	_, _, err = r.run(ctx, composeConfigArgs(spec.Project, file), r.timeout)
	return err
}

// composeFilePath joins and validates spec.Dir and spec.Compose into the
// absolute path of the compose model. Both halfs are validated independently
// (defense in depth against callers bypassing config validation); neither
// half comes from user input at runtime.
func (r *ExecRunner) composeFilePath(spec StackSpec) (string, error) {
	if spec.Dir == "" {
		return "", errors.New("file-backed action: stack has no configured directory")
	}
	if spec.Compose == "" {
		return "", errors.New("file-backed action: no compose file resolved")
	}
	if !validDirString(spec.Dir) {
		return "", fmt.Errorf("invalid stack directory %q", spec.Dir)
	}
	if !validFileNameRegexp.MatchString(spec.Compose) {
		return "", fmt.Errorf("invalid compose file name %q", spec.Compose)
	}
	return filepath.Join(spec.Dir, spec.Compose), nil
}

func validDirString(dir string) bool {
	if dir == "" || !filepath.IsAbs(dir) {
		return false
	}
	return filepath.Clean(dir) == dir
}

func validProject(project string) error {
	if project == "" || !projectRegexp.MatchString(project) {
		return fmt.Errorf("invalid compose project name %q (must match ^[a-z0-9][a-z0-9_-]*$)", project)
	}
	return nil
}

// run executes one command with the given timeout (bounded below by a
// positive default) and captured output. The process is started in its own
// process group so that a timeout (or request cancellation) also kills
// compose's child processes; WaitDelay is a backstop that force-closes the
// stdio pipes if a grandchild ignores that.
func (r *ExecRunner) run(ctx context.Context, args []string, timeout time.Duration) (stdout, stderr []byte, err error) {
	if timeout <= 0 {
		timeout = r.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Env = r.env
	configureProcess(cmd)
	cmd.WaitDelay = 2 * time.Second

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	runErr := cmd.Run()
	if runErr != nil {
		if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, nil, fmt.Errorf("%w: %s %s", ErrTimeout, r.bin, strings.Join(args, " "))
		}
		ce := &CommandError{
			Command:  r.bin + " " + strings.Join(args, " "),
			ExitCode: -1,
			Stderr:   truncate(errBuf.String(), 4096),
		}
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			ce.ExitCode = exitErr.ExitCode()
		}
		return nil, nil, ce
	}
	return outBuf.Bytes(), errBuf.Bytes(), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
