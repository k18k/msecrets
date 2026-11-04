package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	msecrets "github.com/k18k/msecrets"
	"github.com/k18k/msecrets/internal/termui"
)

func optionRows(options []option, c termui.Colors) [][]string {
	rows := make([][]string, 0, len(options))
	for _, o := range options {
		flag := "    "
		if o.short != "" {
			flag = "-" + o.short + ", "
		}
		flag += "--" + o.name
		if o.takesValue {
			placeholder := o.placeholder
			if placeholder == "" {
				placeholder = "VALUE"
			}
			flag += " " + placeholder
		}
		rows = append(rows, []string{"  " + c.Cyan(flag), c.Dim(o.description)})
	}
	return rows
}

func usageLine(spec command) string {
	line := "msecrets " + spec.name
	if spec.args != "" {
		line += " " + spec.args
	}
	return line
}

func specByName(name string) (command, bool) {
	for _, spec := range commands() {
		if spec.name == name {
			return spec, true
		}
	}
	return command{}, false
}

func generalHelp(c termui.Colors) string {
	lines := []string{
		c.Bold("msecrets") + " " + msecrets.Version + ": encrypted secrets that live in your repository",
		"",
		c.Bold("Usage:") + " msecrets <command> [options]",
		"       msecrets              " + c.Dim("open the interactive terminal UI"),
	}
	for _, group := range groups {
		var rows [][]string
		for _, name := range group.names {
			if name == "completion" {
				rows = append(rows, []string{"  " + c.Cyan("completion") + " <SHELL>", c.Dim("Print a shell completion script (bash, zsh, fish, powershell)")})
				continue
			}
			spec, _ := specByName(name)
			label := "  " + c.Cyan(spec.name)
			if spec.args != "" {
				label += " " + spec.args
			}
			rows = append(rows, []string{label, c.Dim(spec.summary)})
		}
		lines = append(lines, "", c.Bold(group.title+":"))
		lines = append(lines, termui.Table(rows)...)
	}
	lines = append(lines, "", c.Bold("Global options:"))
	lines = append(lines, termui.Table(optionRows(globalOptions, c))...)
	lines = append(lines, "",
		"Run "+c.Cyan("msecrets <command> --help")+" for details and examples. Docs: https://k18k.github.io/msecrets/",
		c.Dim("Exit codes: 0 success, 1 failure, 2 usage error, 130 cancelled."))
	return strings.Join(lines, "\n") + "\n"
}

func commandHelp(spec command, c termui.Colors) string {
	lines := []string{c.Bold("Usage:") + " " + usageLine(spec) + " [options]", "", spec.summary}
	if len(spec.examples) > 0 {
		lines = append(lines, "", c.Bold("Examples:"))
		for _, example := range spec.examples {
			if strings.HasPrefix(example, "#") {
				lines = append(lines, "  "+c.Dim(example))
			} else {
				lines = append(lines, "  "+example)
			}
		}
	}
	if len(spec.options) > 0 {
		lines = append(lines, "", c.Bold("Options:"))
		lines = append(lines, termui.Table(optionRows(spec.options, c))...)
	}
	lines = append(lines, "", c.Bold("Global options:"))
	lines = append(lines, termui.Table(optionRows(globalOptions, c))...)
	return strings.Join(lines, "\n") + "\n"
}

func groupHelp(word string, c termui.Colors) string {
	lines := []string{c.Bold("Usage:") + " msecrets " + word + " <command> [options]", "", c.Bold("Commands:")}
	var rows [][]string
	for _, spec := range commands() {
		if strings.HasPrefix(spec.name, word+" ") {
			rows = append(rows, []string{"  " + c.Cyan(spec.name) + strings.TrimRight(" "+spec.args, " "), c.Dim(spec.summary)})
		}
	}
	lines = append(lines, termui.Table(rows)...)
	lines = append(lines, "", "Run "+c.Cyan("msecrets "+word+" <command> --help")+" for details.")
	return strings.Join(lines, "\n") + "\n"
}

// printHelp renders help for any command, including cobra's own (completion).
func printHelp(cmd *cobra.Command, w io.Writer) {
	colors := termui.NewColors(termui.ColorsEnabled(isTerminal(os.Stdout), os.LookupEnv))
	switch {
	case cmd == cmd.Root():
		fmt.Fprint(w, generalHelp(colors))
		return
	case cmd.Annotations["name"] != "":
		spec, _ := specByName(cmd.Annotations["name"])
		fmt.Fprint(w, commandHelp(spec, colors))
		return
	case cmd.Parent() == cmd.Root() && cmd.HasSubCommands() && cmd.Name() != "completion":
		fmt.Fprint(w, groupHelp(cmd.Name(), colors))
		return
	}
	// cobra's commands (completion …): its usage, in the same look.
	fmt.Fprintf(w, "%s %s\n\n%s\n", colors.Bold("Usage:"), cmd.UseLine(), strings.TrimSpace(firstNonEmpty(cmd.Long, cmd.Short)))
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintf(w, "\n%s\n", colors.Bold("Commands:"))
		var rows [][]string
		for _, sub := range cmd.Commands() {
			if sub.IsAvailableCommand() {
				rows = append(rows, []string{"  " + colors.Cyan(sub.Name()), colors.Dim(sub.Short)})
			}
		}
		fmt.Fprintln(w, strings.Join(termui.Table(rows), "\n"))
	}
	if usages := cmd.LocalFlags().FlagUsages(); usages != "" {
		fmt.Fprintf(w, "\n%s\n%s", colors.Bold("Options:"), usages)
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
