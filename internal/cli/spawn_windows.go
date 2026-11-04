package cli

import (
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/k18k/msecrets/internal/core"
)

var forwardedSignals = []os.Signal{os.Interrupt, syscall.SIGHUP}

// setVerbatim passes cmd.exe lines unquoted: core.PlanCommand already escaped every argument.
func setVerbatim(cmd *exec.Cmd, plan core.CommandPlan) {
	if plan.Verbatim {
		cmd.SysProcAttr = &syscall.SysProcAttr{CmdLine: strings.Join(append([]string{plan.File}, plan.Args...), " ")}
	}
}

func exitStatus(state *os.ProcessState) int { return state.ExitCode() }
