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
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Action is one of the state-changing operations on a compose project.
type Action string

const (
	ActionStart   Action = "start"
	ActionStop    Action = "stop"
	ActionRestart Action = "restart"
)

// ParseAction converts a request string into an Action. Unknown strings are
// rejected: they can never reach an argument list.
func ParseAction(s string) (Action, bool) {
	switch Action(s) {
	case ActionStart, ActionStop, ActionRestart:
		return Action(s), true
	default:
		return "", false
	}
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
	// Do performs the given action and returns once the command finished.
	Do(ctx context.Context, project string, action Action) error
}

// projectRegexp mirrors internal/config.ValidProjectName. It is duplicated
// here so the executor refuses to pass any string through to the CLI even if
// a caller bypassed config validation.
var projectRegexp = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// ExecRunner invokes the docker CLI (or another compose-providing binary) in
// the form: <binary> compose -p <project> <subcommand>.
type ExecRunner struct {
	bin     string
	env     []string
	timeout time.Duration
}

// NewExecRunner builds a runner. bin is the compose-providing binary (usually
// "docker"), timeout bounds every single command.
func NewExecRunner(bin string, timeout time.Duration) *ExecRunner {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &ExecRunner{
		bin:     bin,
		env:     minimalEnv(),
		timeout: timeout,
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

// composeActionArgs returns the exact argument list for an action.
func composeActionArgs(project string, action Action) []string {
	return []string{"compose", "-p", project, string(action)}
}

// Status implements Runner.
func (r *ExecRunner) Status(ctx context.Context, project string) (StackStatus, error) {
	if err := validProject(project); err != nil {
		return StackStatus{State: StateUnknown}, err
	}
	stdout, _, err := r.run(ctx, composePSArgs(project))
	if err != nil {
		return StackStatus{State: StateUnknown}, err
	}
	return ParseStatus(stdout)
}

// Do implements Runner.
func (r *ExecRunner) Do(ctx context.Context, project string, action Action) error {
	if err := validProject(project); err != nil {
		return err
	}
	switch action {
	case ActionStart, ActionStop, ActionRestart:
	default:
		return fmt.Errorf("invalid action %q", action)
	}
	_, _, err := r.run(ctx, composeActionArgs(project, action))
	return err
}

func validProject(project string) error {
	if project == "" || !projectRegexp.MatchString(project) {
		return fmt.Errorf("invalid compose project name %q (must match ^[a-z0-9][a-z0-9_-]*$)", project)
	}
	return nil
}

// run executes one command with the runner's timeout and captured output.
// The process is started in its own process group so that a timeout (or
// request cancellation) also kills compose's child processes; WaitDelay is a
// backstop that force-closes the stdio pipes if a grandchild ignores that.
func (r *ExecRunner) run(ctx context.Context, args []string) (stdout, stderr []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.bin, args...)
	cmd.Env = r.env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			// Kill the whole process group (negative pid), not just the CLI.
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
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
