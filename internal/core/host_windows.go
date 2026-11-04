package core

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func setVerbatim(cmd *exec.Cmd, command Command) {
	if command.Verbatim {
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: strings.Join(append([]string{command.Path}, command.Args...), " ")}
	}
}

func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	process.Release()
	return true
}
