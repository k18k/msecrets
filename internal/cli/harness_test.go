package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/creack/pty"
)

// binary is the msecrets binary, built once by TestMain.
var binary string

func TestMain(m *testing.M) {
	if helper(os.Args) {
		return
	}
	directory, err := os.MkdirTemp("", "msecrets-cli-test")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(directory, "msecrets")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "../../cmd/msecrets")
	build.Stdout, build.Stderr = os.Stdout, os.Stderr
	if err := build.Run(); err != nil {
		panic(err)
	}
	code := m.Run()
	os.RemoveAll(directory)
	os.Exit(code)
}

// helper runs the test binary as a stand-in program (a child of `run`, a keychain tool) and reports whether it did.
func helper(args []string) bool {
	switch name := strings.TrimSuffix(filepath.Base(args[0]), ".exe"); {
	case os.Getenv("MSECRETS_TEST_HELPER") == "env":
		// Writes the requested variables (null when unset) as JSON, then exits with MSECRETS_TEST_EXIT.
		values := map[string]*string{}
		for _, key := range strings.Split(os.Getenv("MSECRETS_TEST_VARS"), ",") {
			if value, ok := os.LookupEnv(key); ok {
				values[key] = &value
			} else {
				values[key] = nil
			}
		}
		data, _ := json.Marshal(values)
		_ = os.WriteFile(os.Getenv("MSECRETS_TEST_OUTPUT"), data, 0o644)
		var code int
		fmt.Sscan(os.Getenv("MSECRETS_TEST_EXIT"), &code)
		os.Exit(code)
	case name == "secret-tool" || name == "security":
		fakeKeychain(name, args[1:])
		os.Exit(0)
	}
	return false
}

// fakeKeychain stands in for secret-tool and security, keeping entries in a JSON file.
func fakeKeychain(tool string, args []string) {
	file := os.Getenv("MSECRETS_TEST_KEYCHAIN")
	data := map[string]string{}
	if text, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(text, &data)
	}
	save := func() {
		text, _ := json.Marshal(data)
		_ = os.WriteFile(file, text, 0o600)
	}
	after := func(flag string) string {
		for index, arg := range args {
			if arg == flag && index+1 < len(args) {
				return args[index+1]
			}
		}
		return ""
	}
	stdin := func() string { text, _ := io.ReadAll(os.Stdin); return string(text) }
	if tool == "secret-tool" {
		account := after("account")
		switch args[0] {
		case "lookup":
			value, ok := data[account]
			if !ok {
				os.Exit(1)
			}
			fmt.Print(value)
		case "store":
			data[account] = stdin()
			save()
		case "clear":
			delete(data, account)
			save()
		}
		return
	}
	if args[0] == "-i" {
		words := strings.Fields(stdin())
		for index, word := range words {
			if word == "-a" {
				data[words[index+1]] = words[len(words)-1]
			}
		}
		save()
		return
	}
	account := after("-a")
	value, ok := data[account]
	if !ok {
		os.Exit(44)
	}
	if args[0] == "find-generic-password" {
		fmt.Println(value)
	}
	if args[0] == "delete-generic-password" {
		delete(data, account)
		save()
	}
}

type result struct {
	code           int
	stdout, stderr string
}

type workspace struct {
	root, project, home string
}

func newWorkspace(t *testing.T) *workspace {
	t.Helper()
	root := t.TempDir()
	ws := &workspace{root: root, project: filepath.Join(root, "project"), home: filepath.Join(root, "home")}
	for _, directory := range []string{ws.project, ws.home} {
		if err := os.Mkdir(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return ws
}

type person struct {
	ws     *workspace
	config string
}

func (ws *workspace) person(name string) *person {
	return &person{ws, filepath.Join(ws.root, "config-"+name)}
}

type runOptions struct {
	input string
	env   map[string]string
	cwd   string
}

// environ is a minimal, deterministic environment: no developer config, keychain, or git identity.
func (p *person) environ(extra map[string]string) []string {
	env := map[string]string{
		"PATH":                os.Getenv("PATH"),
		"SystemRoot":          os.Getenv("SystemRoot"),
		"TEMP":                os.TempDir(), // git on Windows writes textconv input to a temp file
		"TMP":                 os.TempDir(),
		"TMPDIR":              os.TempDir(),
		"MSECRETS_CONFIG_DIR": p.config,
		"NO_COLOR":            "1",
		"TERM":                "xterm-256color",
		"HOME":                p.ws.home,
		"USERPROFILE":         p.ws.home,
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_CONFIG_GLOBAL":   filepath.Join(p.ws.home, ".gitconfig"),
	}
	if testing.CoverMode() != "" {
		env["GOCOVERDIR"] = p.ws.home // the test binary stands in for secret-tool; quiet its coverage warning
	}
	for key, value := range extra {
		env[key] = value
	}
	var entries []string
	for key, value := range env {
		entries = append(entries, key+"="+value)
	}
	return entries
}

func (p *person) run(t *testing.T, args []string, options ...runOptions) result {
	t.Helper()
	var o runOptions
	if len(options) > 0 {
		o = options[0]
	}
	cmd := exec.Command(binary, args...)
	cmd.Env = p.environ(o.env)
	cmd.Dir = firstNonEmpty(o.cwd, p.ws.project)
	cmd.Stdin = strings.NewReader(o.input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return result{code, stdout.String(), stderr.String()}
}

func ok(t *testing.T, r result) {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("exit code %d\nstdout: %s\nstderr: %s", r.code, r.stdout, r.stderr)
	}
}

func expectCode(t *testing.T, r result, code int) {
	t.Helper()
	if r.code != code {
		t.Fatalf("exit code %d, want %d\nstdout: %s\nstderr: %s", r.code, code, r.stdout, r.stderr)
	}
}

func expectMatch(t *testing.T, text, pattern string) {
	t.Helper()
	if !regexp.MustCompile(pattern).MatchString(text) {
		t.Fatalf("%q does not match %s", text, pattern)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// identityFrom extracts the identity line from `--store print` / `--generate` output.
func identityFrom(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			return line
		}
	}
	return ""
}

// exchange answers a prompt: when stderr (ANSI stripped) matches prompt, answer is typed.
type exchange struct {
	prompt string
	answer string
}

type ptyOptions struct {
	stdoutIsTerminal bool
	env              map[string]string
}

type ptyResult struct {
	result
	// screen is everything written to the terminal, without ANSI sequences.
	screen     string
	unanswered int
}

// interactive runs a command on a pseudo-terminal (stdin and stderr; stdout too if asked)
// and types each answer when its prompt appears, like a person would.
func (p *person) interactive(t *testing.T, args []string, exchanges []exchange, options ...ptyOptions) ptyResult {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("pseudo-terminals: POSIX only")
	}
	var o ptyOptions
	if len(options) > 0 {
		o = options[0]
	}
	terminal, tty, err := pty.Open()
	if err != nil {
		t.Skip("no pseudo-terminal:", err)
	}
	defer terminal.Close()
	_ = pty.Setsize(terminal, &pty.Winsize{Rows: 30, Cols: 110})
	cmd := exec.Command(binary, args...)
	cmd.Env = p.environ(o.env)
	cmd.Dir = p.ws.project
	var stdout, stderr bytes.Buffer
	cmd.Stdin, cmd.Stderr = tty, tty
	cmd.Stdout = &stdout
	if o.stdoutIsTerminal {
		cmd.Stdout = tty
	}
	setControllingTerminal(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	tty.Close()

	var mu sync.Mutex
	var screen strings.Builder
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, err := terminal.Read(buffer)
			mu.Lock()
			screen.Write(buffer[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	seen := 0
	pending := exchanges
	deadline := time.Now().Add(20 * time.Second)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	var waitErr error
loop:
	for {
		select {
		case waitErr = <-exited:
			break loop
		case <-time.After(10 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("timed out; screen: %q", ansi.Strip(screen.String()))
		}
		mu.Lock()
		text := ansi.Strip(screen.String())
		mu.Unlock()
		// Prompts wider than the terminal wrap; match them as one line.
		if len(pending) > 0 && regexp.MustCompile(pending[0].prompt).MatchString(strings.NewReplacer("\r", "", "\n", "").Replace(text[seen:])) {
			seen = len(text)
			if pending[0].prompt != "" {
				// Let the prompt finish starting (raw mode) before typing. An empty prompt
				// continues the previous answer: a separate read within milliseconds.
				time.Sleep(100 * time.Millisecond)
			}
			if _, err := terminal.Write([]byte(pending[0].answer)); err != nil {
				t.Fatal(err)
			}
			pending = pending[1:]
		}
	}
	time.Sleep(50 * time.Millisecond)
	code := 0
	if exit, ok := waitErr.(*exec.ExitError); ok {
		code = exit.ExitCode()
	}
	mu.Lock()
	defer mu.Unlock()
	raw := screen.String()
	_ = stderr
	return ptyResult{result{code, stdout.String(), raw}, ansi.Strip(raw), len(pending)}
}
