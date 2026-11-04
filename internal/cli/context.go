package cli

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/term"

	"github.com/k18k/msecrets/internal/core"
	"github.com/k18k/msecrets/internal/termui"
)

// GlobalOptions are the options every command takes.
type GlobalOptions struct {
	File     string
	Env      string
	Identity []string
	As       string
}

// Context is what a command touches outside the process.
type Context struct {
	Host           core.Host
	Stdin          *os.File
	Stdout, Stderr io.Writer
	// Terminal state of the standard streams.
	StdinTTY, StdoutTTY, StderrTTY bool
	Cwd                            string
	Options                        GlobalOptions
	Out, Err                       termui.Colors
	Symbols                        termui.Symbols

	path       string
	identities []core.LoadedIdentity
	loaded     bool
	childEnv   map[string]string
}

func isTerminal(file *os.File) bool { return term.IsTerminal(int(file.Fd())) }

// newContext describes the running process.
func newContext(options GlobalOptions) (*Context, error) {
	h := core.NativeHost()
	cwd, err := h.Getwd()
	if err != nil {
		return nil, err
	}
	c := &Context{
		Host: h, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		StdinTTY: isTerminal(os.Stdin), StdoutTTY: isTerminal(os.Stdout), StderrTTY: isTerminal(os.Stderr),
		Cwd: cwd, Options: options,
	}
	c.Out = termui.NewColors(termui.ColorsEnabled(c.StdoutTTY, h.LookupEnv))
	c.Err = termui.NewColors(termui.ColorsEnabled(c.StderrTTY, h.LookupEnv))
	c.Symbols = termui.NewSymbols(termui.SupportsUnicode(h.LookupEnv, h.Platform()))
	return c, nil
}

func (c *Context) getenv(key string) string {
	value, _ := c.Host.LookupEnv(key)
	return value
}

// Print writes a line to stdout.
func (c *Context) Print(text string) { fmt.Fprintln(c.Stdout, text) }

// Note writes a line to stderr: diagnostics stay out of machine-readable stdout.
func (c *Context) Note(text string) { fmt.Fprintln(c.Stderr, text) }

// Warn writes a warning to stderr.
func (c *Context) Warn(text string) { c.Note(c.Err.Yellow("warning: " + text)) }

// Success writes a check mark and text to stderr.
func (c *Context) Success(text string) { c.Note(c.Err.Green(c.Symbols.Check) + " " + text) }

// Path is the secrets file.
func (c *Context) Path() (string, error) {
	if c.path == "" {
		path, err := core.ResolveDocumentFile(c.Host, c.Options.File, c.Cwd)
		if err != nil {
			return "", err
		}
		c.path = path
	}
	return c.path, nil
}

// targetPath is the path of a file that may not exist yet (init).
func (c *Context) targetPath() string {
	name := c.Options.File
	if name == "" {
		name = c.getenv("MSECRETS_FILE")
	}
	if name == "" {
		name = core.DefaultFilename
	}
	if filepath.IsAbs(name) {
		return filepath.Clean(name)
	}
	return filepath.Join(c.Cwd, name)
}

// DisplayPath shows a path relative to the working directory when it is inside it.
func (c *Context) DisplayPath(path string) string {
	relative, err := filepath.Rel(c.Cwd, path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return path
	}
	return relative
}

// Document reads the secrets file.
func (c *Context) Document() (*core.Document, error) {
	path, err := c.Path()
	if err != nil {
		return nil, err
	}
	return core.ReadDocumentFile(c.Host, path)
}

// update runs a mutation on the secrets file (locked, validated, atomic).
func update[T any](c *Context, mutate func(*core.Document) (T, error)) (T, error) {
	path, err := c.Path()
	if err != nil {
		var zero T
		return zero, err
	}
	return core.UpdateDocumentFile(c.Host, path, mutate)
}

// Environment chooses the environment: explicit, then --env, then the core defaults.
func (c *Context) Environment(document *core.Document, explicit string) (string, error) {
	if explicit == "" {
		explicit = c.Options.Env
	}
	choice, err := core.ChooseEnvironment(c.Host, document, explicit)
	return choice.Name, err
}

var rawIdentity = regexp.MustCompile(`(?i)^AGE-SECRET-KEY-`)

// sources are the identity sources, reading a copy of the environment that they scrub.
func (c *Context) sources(passphrase func(string) (string, error), h core.Host) ([]core.IdentitySource, error) {
	options := core.SourceOptions{Host: h, Cwd: c.Cwd, Passphrase: passphrase}
	if len(c.Options.Identity) == 0 {
		return []core.IdentitySource{core.AutoSource(options)}, nil
	}
	sources := make([]core.IdentitySource, len(c.Options.Identity))
	for index, spec := range c.Options.Identity {
		if rawIdentity.MatchString(strings.TrimSpace(spec)) {
			sources[index] = core.FromString(spec, "--identity", options)
			continue
		}
		source, err := core.ParseSourceSpec(spec, options)
		if err != nil {
			return nil, err
		}
		sources[index] = source
	}
	return sources, nil
}

type passphraseNeeded struct{ label string }

func (e *passphraseNeeded) Error() string { return "Passphrase needed for " + e.label }

// LoadedIdentities loads identities, prompting for passphrases on a terminal when needed.
func (c *Context) LoadedIdentities() ([]core.LoadedIdentity, error) {
	if c.loaded {
		return c.identities, nil
	}
	passphrases := map[string]string{}
	fromEnv, haveEnv := c.Host.LookupEnv(core.PassphraseVariable)
	for {
		// Every attempt starts from the full environment; sources delete the variables they read.
		env := environMap(c.Host.Environ())
		sources, err := c.sources(func(label string) (string, error) {
			if known, ok := passphrases[label]; ok {
				return known, nil
			}
			if haveEnv {
				return fromEnv, nil
			}
			return "", &passphraseNeeded{label}
		}, core.WithEnv(c.Host, env))
		if err != nil {
			return nil, err
		}
		loaded, err := core.LoadIdentities(sources)
		if err == nil {
			c.identities, c.loaded, c.childEnv = loaded, true, env
			return loaded, nil
		}
		var needed *passphraseNeeded
		if !errors.As(err, &needed) {
			return nil, err
		}
		if _, asked := passphrases[needed.label]; asked {
			return nil, err
		}
		if !c.StdinTTY {
			return nil, &core.Error{Code: core.CodeIdentitySource, Message: fmt.Sprintf("%s is passphrase-protected; set %s", needed.label, core.PassphraseVariable)}
		}
		answer, err := c.Ask(fmt.Sprintf("Passphrase for %s: ", needed.label), true)
		if err != nil {
			return nil, err
		}
		passphrases[needed.label] = answer
	}
}

func environMap(entries []string) map[string]string {
	env := map[string]string{}
	for _, entry := range entries {
		if key, value, ok := strings.Cut(entry, "="); ok && key != "" {
			env[key] = value
		}
	}
	return env
}

// ChildEnv is the environment for commands msecrets runs: without any variable an
// identity was read from (env:NAME sources included) and without msecrets key settings.
func (c *Context) ChildEnv() (map[string]string, error) {
	if _, err := c.LoadedIdentities(); err != nil {
		return nil, err
	}
	env := maps.Clone(c.childEnv)
	for _, variable := range []string{core.IdentityVariable, core.IdentityFileVariable, core.IdentitySourceVariable, core.PassphraseVariable} {
		delete(env, variable)
	}
	return env, nil
}

// Identities are the loaded private keys.
func (c *Context) Identities() ([]*core.Identity, error) {
	loaded, err := c.LoadedIdentities()
	if err != nil {
		return nil, err
	}
	identities := make([]*core.Identity, len(loaded))
	for index, entry := range loaded {
		identities[index] = entry.Identity
	}
	return identities, nil
}

// RequireIdentities fails with setup guidance when there are no identities.
func (c *Context) RequireIdentities() ([]*core.Identity, error) {
	identities, err := c.Identities()
	if err == nil && len(identities) == 0 {
		err = &core.Error{Code: core.CodeIdentitySource, Message: "No msecrets identity found. Create one with `msecrets identity new`, or point to one with --identity, MSECRETS_IDENTITY, or `msecrets identity use <source>`"}
	}
	return identities, err
}

func usageError(format string, args ...any) error {
	return &core.Error{Code: core.CodeUsage, Message: fmt.Sprintf(format, args...)}
}

func coreError(code core.ErrorCode, format string, args ...any) error {
	return &core.Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
