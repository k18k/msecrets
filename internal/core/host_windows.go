package core

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// retryShared retries file operations that fail because another process has the file open:
// Go opens files without FILE_SHARE_DELETE, so a concurrent reader (another msecrets
// waiting for the lock) briefly blocks deleting or replacing the file.
func retryShared(operation func() error) error {
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := operation()
		var code syscall.Errno
		if err == nil || !errors.As(err, &code) || (code != 5 && code != 32 && code != 33) || time.Now().After(deadline) {
			return err // 5: access denied, 32: sharing violation, 33: lock violation
		}
		time.Sleep(10 * time.Millisecond)
	}
}

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
