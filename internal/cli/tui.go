package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/k18k/msecrets/internal/tui"
)

// runTUI loads identities first (passphrase prompts need the normal terminal mode), then opens the UI.
func runTUI(c *Context) error {
	path, err := c.Path()
	if err != nil {
		return err
	}
	identities, err := c.Identities()
	problem := ""
	if err != nil {
		problem, _, _ = strings.Cut(err.Error(), "\n")
		identities = nil
	} else if len(identities) == 0 {
		problem = "no identity found (run `msecrets identity new`)"
	}
	app, err := tui.New(tui.Options{Host: c.Host, Path: path, Cwd: c.Cwd, Identities: identities, Problem: problem, Colors: c.Out, Symbols: c.Symbols})
	if err != nil {
		return err
	}
	return tui.Run(app)
}

// completeWith completes a flag value from names in the secrets file.
func completeWith(names func(*Context) []string) func(*cobra.Command, []string, string) ([]cobra.Completion, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, _ []string, _ string) ([]cobra.Completion, cobra.ShellCompDirective) {
		c, err := newContext(globalsFrom(flags{cmd.Flags()}))
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		return names(c), cobra.ShellCompDirectiveNoFileComp
	}
}
