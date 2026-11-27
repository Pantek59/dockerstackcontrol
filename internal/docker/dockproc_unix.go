//go:build !windows

package docker

import (
	"os/exec"
	"syscall"
)

// configureProcess starts the command in its own process group and arranges
// a group-wide kill on cancellation (mirrors the unix behavior needed by the
// compose CLI, which spawns child processes). On timeout, WaitDelay closes
// the stdio pipes so a grandchild cannot block Wait indefinitely.
func configureProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			// Kill the whole process group (negative pid), not just the CLI.
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
}
