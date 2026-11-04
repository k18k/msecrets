package core

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"time"
)

// Host is everything core needs from the operating system: environment
// variables, files, the working and home directories, and processes. All
// system access goes through it, so that core also runs where the os and
// os/exec packages do not work synchronously (js/wasm under Node.js).
//
// [NativeHost] implements it with the os and os/exec packages.
type Host interface {
	// LookupEnv returns an environment variable.
	LookupEnv(key string) (string, bool)
	// Unsetenv deletes an environment variable.
	Unsetenv(key string) error
	// Environ returns the environment as "KEY=value" entries.
	Environ() []string

	// ReadFile reads a file. Missing files yield an error wrapping fs.ErrNotExist.
	ReadFile(path string) ([]byte, error)
	// CreateFile creates a new file with mode 0644, writes data, and syncs it to disk.
	// It fails with an error wrapping fs.ErrExist if the file exists.
	CreateFile(path string, data []byte) error
	// Rename atomically replaces to with from.
	Rename(from, to string) error
	// Remove deletes a file; a missing file is not an error.
	Remove(path string) error
	// Stat describes a file. Missing files yield an error wrapping fs.ErrNotExist.
	Stat(path string) (fs.FileInfo, error)

	// Getwd returns the working directory.
	Getwd() (string, error)
	// HomeDir returns the home directory of the user.
	HomeDir() (string, error)
	// Platform returns the operating system in GOOS terms: "linux", "darwin", "windows", ….
	Platform() string

	// Pid returns the process id of this process.
	Pid() int
	// ProcessExists reports whether a process with the id exists.
	ProcessExists(pid int) bool
	// Sleep pauses the calling goroutine.
	Sleep(duration time.Duration)
	// Run runs a command to completion. A command that cannot be found yields an
	// error wrapping fs.ErrNotExist; a command that runs and fails is not an error.
	Run(command Command) (CommandResult, error)
}

// Command is a process to run, without a shell.
type Command struct {
	// Path is the program; without a path separator, it is looked up in PATH.
	Path string
	Args []string
	// Env is the environment of the process ("KEY=value").
	Env []string
	// Dir is the working directory ("" for the current one).
	Dir string
	// Stdin is written to the standard input of the process, unless Interactive is set.
	Stdin []byte
	// Interactive lets the process use the terminal: it inherits standard input and standard error.
	Interactive bool
	// Timeout kills the process after this duration (0: none).
	Timeout time.Duration
	// MaxOutput fails the command when it writes more than this many bytes to an output (0: no limit).
	MaxOutput int
	// Verbatim passes Args to the process unquoted (Windows; see [PlanCommand]).
	Verbatim bool
}

// CommandResult is the outcome of a command that ran.
type CommandResult struct {
	Stdout []byte
	Stderr []byte
	// ExitCode is the exit status, or -1 when the process was killed by a signal.
	ExitCode int
	// Signal describes the signal that killed the process, if any.
	Signal string
}

// NativeHost returns the Host of the running process (os and os/exec).
func NativeHost() Host { return nativeHost{} }

type nativeHost struct{}

func (nativeHost) LookupEnv(key string) (string, bool) { return os.LookupEnv(key) }
func (nativeHost) Unsetenv(key string) error           { return os.Unsetenv(key) }
func (nativeHost) Environ() []string                   { return os.Environ() }
func (nativeHost) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (nativeHost) CreateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}

func (nativeHost) Rename(from, to string) error {
	return retryShared(func() error { return os.Rename(from, to) })
}

func (nativeHost) Remove(path string) error {
	if err := retryShared(func() error { return os.Remove(path) }); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func (nativeHost) Stat(path string) (fs.FileInfo, error) { return os.Stat(path) }
func (nativeHost) Getwd() (string, error)                { return os.Getwd() }
func (nativeHost) HomeDir() (string, error)              { return os.UserHomeDir() }
func (nativeHost) Platform() string                      { return runtime.GOOS }
func (nativeHost) Pid() int                              { return os.Getpid() }
func (nativeHost) ProcessExists(pid int) bool            { return processExists(pid) }
func (nativeHost) Sleep(duration time.Duration)          { time.Sleep(duration) }

// limitedBuffer fails writes beyond its limit.
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit > 0 && b.Len()+len(p) > b.limit {
		return 0, fmt.Errorf("output exceeds %d bytes", b.limit)
	}
	return b.Buffer.Write(p)
}

func (nativeHost) Run(command Command) (CommandResult, error) {
	ctx := context.Background()
	if command.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, command.Timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, command.Path, command.Args...)
	cmd.Env = command.Env
	cmd.Dir = command.Dir
	setVerbatim(cmd, command)
	stdout := &limitedBuffer{limit: command.MaxOutput}
	stderr := &limitedBuffer{limit: command.MaxOutput}
	cmd.Stdout = stdout
	if command.Interactive {
		cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	} else {
		cmd.Stdin, cmd.Stderr = bytes.NewReader(command.Stdin), stderr
	}

	err := cmd.Run()
	var exitError *exec.ExitError
	switch {
	case errors.As(err, &exitError):
		result := CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitError.ExitCode()}
		if result.ExitCode == -1 {
			result.Signal = exitError.String()
		}
		return result, nil
	case errors.Is(err, exec.ErrNotFound):
		return CommandResult{}, fmt.Errorf("%w: %w", fs.ErrNotExist, err)
	case err != nil:
		return CommandResult{}, err
	}
	return CommandResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}, nil
}

// WithEnv returns a Host that reads and scrubs env (a map it mutates) instead
// of the environment of base, for example a copy of the environment that
// identity sources scrub before a child process gets it.
func WithEnv(base Host, env map[string]string) Host { return envHost{base, env} }

type envHost struct {
	Host
	env map[string]string
}

func (h envHost) LookupEnv(key string) (string, bool) {
	value, ok := h.env[key]
	return value, ok
}

func (h envHost) Unsetenv(key string) error {
	delete(h.env, key)
	return nil
}

func (h envHost) Environ() []string {
	entries := []string{}
	for _, key := range slices.Sorted(maps.Keys(h.env)) {
		entries = append(entries, key+"="+h.env[key])
	}
	return entries
}

func getenv(h Host, key string) string {
	value, _ := h.LookupEnv(key)
	return value
}
