//go:build !windows

package core

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

func setVerbatim(*exec.Cmd, Command) {}

func retryShared(operation func() error) error { return operation() }

func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}
