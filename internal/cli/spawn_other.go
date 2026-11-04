//go:build !windows

package cli

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/k18k/msecrets/internal/core"
)

var forwardedSignals = []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

func setVerbatim(*exec.Cmd, core.CommandPlan) {}

// exitStatus is the exit code, or 128+signal (the shell convention) for a child killed by a signal.
func exitStatus(state *os.ProcessState) int {
	if status, ok := state.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return state.ExitCode()
}
