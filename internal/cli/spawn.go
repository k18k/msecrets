package cli

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"sort"

	"github.com/k18k/msecrets/internal/core"
)

const runUsage = "No command given; usage: msecrets run [--env NAME] -- <command> [args...]"

// runCommand runs argv with inherited stdio to completion and returns its exit
// code. Termination signals are forwarded; SIGINT only without a terminal,
// since a terminal already delivers Ctrl-C to the whole process group.
func runCommand(c *Context, argv []string, env map[string]string) (int, error) {
	if len(argv) == 0 {
		return 0, usageError(runUsage)
	}
	plan, err := core.PlanCommand(core.WithEnv(c.Host, env), argv, c.Cwd)
	if err != nil {
		return 0, usageError(runUsage)
	}
	cmd := exec.Command(plan.File, plan.Args...)
	setVerbatim(cmd, plan)
	cmd.Dir = c.Cwd
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = make([]string, 0, len(env))
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	sort.Strings(cmd.Env)

	signals := make(chan os.Signal, 4)
	signal.Notify(signals, forwardedSignals...)
	defer signal.Stop(signals)
	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return 0, usageError("Command not found: %s", plan.File)
		}
		return 0, usageError("Failed to start %s: %v", plan.File, err)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case received := <-signals:
				if received != os.Interrupt || !c.StdinTTY {
					_ = cmd.Process.Signal(received)
				}
			case <-done:
				return
			}
		}
	}()
	err = cmd.Wait()
	close(done)
	var exitError *exec.ExitError
	if err != nil && !errors.As(err, &exitError) {
		return 0, err
	}
	return exitStatus(cmd.ProcessState), nil
}
