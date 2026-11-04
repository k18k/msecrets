//go:build !windows

package cli

import (
	"os/exec"
	"syscall"
)

func setControllingTerminal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
}
