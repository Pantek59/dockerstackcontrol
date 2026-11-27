//go:build windows

package docker

import (
	"os/exec"
	"strconv"
)

// configureProcess prepares process teardown on Windows: there are no process
// groups, so cancellation kills the whole process tree with taskkill (the
// docker CLI spawns the compose plugin as a child). Taskkill ships with every
// Windows installation; it is invoked directly, without a shell.
func configureProcess(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		treeKill := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
		if err := treeKill.Run(); err != nil {
			// Fall back to a single-process kill if taskkill is unavailable
			// or refuses (process already exited).
			return cmd.Process.Kill()
		}
		return nil
	}
}
