// Package cli is the msecrets command line: every command, its options and
// help, and the git integration. Commands only call core and render results.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	msecrets "github.com/k18k/msecrets"
	"github.com/k18k/msecrets/internal/core"
	"github.com/k18k/msecrets/internal/termui"
)

// option is a command-line option.
type option struct {
	name, short string
	// takesValue: a string option (otherwise boolean).
	takesValue  bool
	multiple    bool
	description string
	placeholder string
}

// command is one msecrets command, e.g. "env add".
type command struct {
	name, args, summary string
	examples            []string
	options             []option
	// passthrough: everything after the first positional (or --) is passed through verbatim.
	passthrough bool
	// complete completes positional arguments.
	complete func(c *Context, args []string) []string
	run      func(c *Context, args []string, f flags) (int, error)
}

var globalOptions = []option{
	{name: "file", short: "f", takesValue: true, placeholder: "PATH", description: "Secrets file (default: MSECRETS_FILE, else msecrets.json here or in a parent directory)"},
	{name: "env", short: "e", takesValue: true, multiple: true, placeholder: "NAME", description: "Environment (default: MSECRETS_ENV, else development, else the only one)"},
	{name: "identity", short: "i", takesValue: true, multiple: true, placeholder: "SOURCE", description: "Identity source or key to use instead of the defaults"},
	{name: "as", takesValue: true, placeholder: "RECIPIENT", description: "Sign changes as this recipient"},
	{name: "help", short: "h", description: "Show help"},
}

var groups = []struct {
	title string
	names []string
}{
	{"Get started", []string{"init", "join", "whoami", "identity new", "identity show", "identity use", "identity export"}},
	{"Secrets", []string{"ls", "get", "set", "unset", "rm", "mv", "describe", "scope"}},
	{"Environments", []string{"env ls", "env add", "env rm", "env mv"}},
	{"Access", []string{"recipient ls", "recipient add", "recipient rm", "recipient mv", "recipient rotate", "grant", "revoke", "sync"}},
	{"Run your app", []string{"run", "export", "import"}},
	{"CI and git", []string{"check", "git setup", "git textconv", "git merge-driver"}},
	{"AI agents and shells", []string{"skill", "completion"}},
}

// flags reads parsed options.
type flags struct{ set *pflag.FlagSet }

func (f flags) Bool(name string) bool {
	value, _ := f.set.GetBool(name)
	return value
}

// String is the last value of a string option ("" if not given).
func (f flags) String(name string) string {
	if values, err := f.set.GetStringArray(name); err == nil {
		if len(values) == 0 {
			return ""
		}
		return values[len(values)-1]
	}
	value, _ := f.set.GetString(name)
	return value
}

// Has reports whether an option was given.
func (f flags) Has(name string) bool { return f.set.Changed(name) }

// List is a repeatable, comma-separated option.
func (f flags) List(name string) []string {
	values, err := f.set.GetStringArray(name)
	if err != nil {
		values = []string{f.String(name)}
	}
	return splitList(values)
}

func splitList(values []string) []string {
	list := []string{}
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if part = strings.TrimSpace(part); part != "" {
				list = append(list, part)
			}
		}
	}
	return list
}

func addOption(set *pflag.FlagSet, o option) {
	switch {
	case o.name == "help":
		set.BoolP("help", "h", false, o.description)
	case o.multiple:
		set.StringArrayP(o.name, o.short, nil, o.description)
	case o.takesValue:
		set.StringP(o.name, o.short, "", o.description)
	default:
		set.BoolP(o.name, o.short, false, o.description)
	}
}

func requireArgs(args []string, count int, usage string) error {
	if len(args) < count {
		return usageError("Missing arguments; usage: msecrets %s", usage)
	}
	return nil
}

// exitError carries an exit code without a message (the command already reported).
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit code %d", e.code) }

func globalsFrom(f flags) GlobalOptions {
	options := GlobalOptions{File: f.String("file"), Identity: nil, As: f.String("as")}
	if environments := f.List("env"); len(environments) > 0 {
		options.Env = environments[0]
	}
	if identities, _ := f.set.GetStringArray("identity"); len(identities) > 0 {
		options.Identity = identities
	}
	return options
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "msecrets",
		Short:         "encrypted secrets that live in your repository",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return unknownCommand(args)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTerminalUI(cmd, false)
		},
		CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: false},
	}
	for _, o := range globalOptions {
		if o.name != "help" {
			addOption(root.PersistentFlags(), o)
		}
	}
	_ = root.RegisterFlagCompletionFunc("env", completeWith(environmentNames))
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return usageError("%s. Run `%s --help`", flagErrorMessage(err), cmd.CommandPath())
	})
	root.SetHelpFunc(func(cmd *cobra.Command, _ []string) { printHelp(cmd, os.Stdout) })
	root.SetHelpCommand(&cobra.Command{
		Use:    "help [command]",
		Short:  "Show help for a command",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				printHelp(root, os.Stdout)
				return nil
			}
			found, rest, err := root.Find(args)
			if err != nil || len(rest) > 0 || found == root {
				return unknownCommand(args)
			}
			printHelp(found, os.Stdout)
			return nil
		},
	})
	root.AddCommand(&cobra.Command{
		Use:   "tui",
		Short: "Open the interactive terminal UI",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return runTerminalUI(cmd, true) },
	})

	parents := map[string]*cobra.Command{}
	for _, spec := range commands() {
		parent := root
		words := strings.Fields(spec.name)
		if len(words) == 2 {
			parent = parents[words[0]]
			if parent == nil {
				parent = groupCommand(words[0])
				parents[words[0]] = parent
				root.AddCommand(parent)
			}
		}
		parent.AddCommand(cobraCommand(spec, words[len(words)-1]))
	}
	return root
}

func flagErrorMessage(err error) string {
	message := err.Error()
	if name, ok := strings.CutPrefix(message, "unknown flag: "); ok {
		return "Unknown option '" + name + "'"
	}
	if name, ok := strings.CutPrefix(message, "unknown shorthand flag: "); ok {
		return "Unknown option " + name
	}
	return strings.ToUpper(message[:1]) + message[1:]
}

// groupCommand is a word that only groups subcommands ("env", "recipient", …).
func groupCommand(word string) *cobra.Command {
	return &cobra.Command{
		Use:               word,
		Short:             "",
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(_ *cobra.Command, args []string) error {
			return unknownCommand(append([]string{word}, args...))
		},
	}
}

func cobraCommand(spec command, word string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   word,
		Short: spec.summary,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f := flags{cmd.Flags()}
			c, err := newContext(globalsFrom(f))
			if err != nil {
				return err
			}
			code, err := spec.run(c, args, f)
			if err == nil && code != 0 {
				err = &exitError{code}
			}
			return err
		},
	}
	cmd.Annotations = map[string]string{"args": spec.args, "name": spec.name}
	if len(spec.examples) > 0 {
		cmd.Example = strings.Join(spec.examples, "\n")
	}
	for _, o := range spec.options {
		addOption(cmd.Flags(), o)
	}
	if spec.passthrough {
		cmd.Flags().SetInterspersed(false)
	}
	cmd.ValidArgsFunction = func(cobraCmd *cobra.Command, args []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
		if spec.complete == nil {
			if spec.passthrough {
				return nil, cobra.ShellCompDirectiveDefault
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		c, err := newContext(globalsFrom(flags{cobraCmd.Flags()}))
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		return spec.complete(c, args), cobra.ShellCompDirectiveNoFileComp
	}
	return cmd
}

func unknownCommand(words []string) error {
	words = words[:min(2, len(words))]
	first := words[0]
	var hint string
	var subcommands, names []string
	for _, spec := range commands() {
		word, _, _ := strings.Cut(spec.name, " ")
		if strings.HasPrefix(spec.name, first+" ") {
			subcommands = append(subcommands, spec.name)
		}
		if !slices.Contains(names, word) {
			names = append(names, word)
		}
	}
	if len(subcommands) > 0 {
		hint = " (try: " + strings.Join(subcommands, ", ") + ")"
	} else {
		hint = core.Suggest(first, append(names, "completion", "tui", "help"))
	}
	return usageError("Unknown command \"%s\"%s. Run `msecrets --help`", termui.Sanitize(strings.Join(words, " ")), hint)
}

func runTerminalUI(cmd *cobra.Command, explicit bool) error {
	c, err := newContext(globalsFrom(flags{cmd.Flags()}))
	if err != nil {
		return err
	}
	if !c.StdinTTY || !c.StdoutTTY {
		if explicit {
			return usageError("The terminal UI needs an interactive terminal")
		}
		printHelp(cmd.Root(), os.Stdout)
		return nil
	}
	return runTUI(c)
}

// Main runs the CLI with arguments (without the program name) and returns the exit code.
func Main(argv []string) int {
	stderrColors := termui.NewColors(termui.ColorsEnabled(isTerminal(os.Stderr), os.LookupEnv))
	if len(argv) > 0 && (argv[0] == "--version" || argv[0] == "-v" || argv[0] == "version") {
		fmt.Println("msecrets " + msecrets.Version)
		return 0
	}
	root := newRoot()
	root.SetArgs(argv)
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	err := root.Execute()
	return reportError(err, os.Stderr, stderrColors)
}

func reportError(err error, stderr io.Writer, colors termui.Colors) int {
	var exit *exitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.code
	case errors.Is(err, errCancelled):
		fmt.Fprintln(stderr)
		return 130
	}
	message := err.Error()
	var coreErr *core.Error
	if errors.As(err, &coreErr) && coreErr.Code != core.CodeUsage {
		// The code lets scripts and agents match failures (NOT_FOUND, ACCESS_DENIED, …).
		message += colors.Dim(" [" + string(coreErr.Code) + "]")
	} else if !errors.As(err, &coreErr) && strings.HasPrefix(message, "unknown command") {
		message = strings.ToUpper(message[:1]) + message[1:]
	}
	fmt.Fprintf(stderr, "%s %s\n", colors.Red("msecrets:"), message)
	if errors.As(err, &coreErr) && coreErr.Code == core.CodeUsage {
		return 2
	}
	return 1
}
