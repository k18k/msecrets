package cli

import (
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/k18k/msecrets/internal/core"
	"github.com/k18k/msecrets/internal/termui"
)

var lsCommand = command{
	name:     "ls",
	summary:  "Show every secret in every environment, and any problems (use `check` to fail CI)",
	examples: []string{"msecrets ls", "msecrets ls --json | jq '.secrets | keys'"},
	options:  []option{optJSON},
	run: func(c *Context, _ []string, f flags) (int, error) {
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		report, err := core.Inspect(document)
		if err != nil {
			return 0, err
		}
		environments := document.Environments.Keys()
		path, _ := c.Path()

		if f.Bool("json") {
			secrets := orderedObject{}
			for name, secret := range document.Secrets.All() {
				entry := orderedObject{}
				if secret.Description != "" {
					entry.add("description", secret.Description)
				}
				values := orderedObject{}
				for _, cell := range report.Cells {
					if cell.Secret == name {
						values.add(cell.Environment, cell.State)
					}
				}
				entry.add("values", values)
				secrets.add(name, entry)
			}
			object := orderedObject{}
			object.add("file", path)
			object.add("environments", environments)
			object.add("secrets", secrets)
			object.add("findings", findingsJSON(report))
			object.add("ok", report.OK)
			text, err := jsonText(object)
			c.Print(text)
			return 0, err
		}

		if document.Secrets.Len() == 0 {
			c.Print(fmt.Sprintf("No secrets yet in %s. Add one with `msecrets set NAME`.", c.DisplayPath(path)))
			return 0, nil
		}
		header := []string{c.Out.Bold("SECRET")}
		for _, environment := range environments {
			header = append(header, c.Out.Bold(environment))
		}
		rows := [][]string{append(header, c.Out.Bold("DESCRIPTION"))}
		for name, secret := range document.Secrets.All() {
			row := []string{name}
			for _, environment := range environments {
				row = append(row, cellGlyph(c, cellState(report, name, environment)))
			}
			rows = append(rows, append(row, c.Out.Dim(secret.Description)))
		}
		for _, line := range termui.Table(rows) {
			c.Print(line)
		}
		var legend []string
		for _, state := range termui.LegendStates {
			legend = append(legend, cellGlyph(c, state)+" "+termui.CellDescriptions[state])
		}
		c.Print(c.Out.Dim("\n" + strings.Join(legend, "   ")))
		if len(report.Findings) > 0 {
			c.Print("")
			printFindings(c, report)
		}
		return 0, nil
	},
}

var checkCommand = command{
	name:     "check",
	summary:  "Validate the file for CI: every value present, current, and signed (exit 1 otherwise)",
	examples: []string{"msecrets check", "msecrets check --json"},
	options:  []option{optJSON},
	run: func(c *Context, _ []string, f flags) (int, error) {
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		report, err := core.Inspect(document)
		if err != nil {
			return 0, err
		}
		path, _ := c.Path()
		code := 0
		if !report.OK {
			code = 1
		}
		if f.Bool("json") {
			object := orderedObject{}
			object.add("file", path)
			object.add("ok", report.OK)
			object.add("findings", findingsJSON(report))
			text, err := jsonText(object)
			c.Print(text)
			return code, err
		}
		printFindings(c, report)
		counts := fmt.Sprintf("%d secret(s) × %d environment(s)", document.Secrets.Len(), document.Environments.Len())
		if report.OK {
			c.Print(fmt.Sprintf("%s %s: %s; every value is present, current, and signed", c.Out.Green(c.Symbols.Check), c.DisplayPath(path), counts))
		} else {
			c.Print(fmt.Sprintf("%s %s: %s; fix the errors above", c.Out.Red(c.Symbols.Cross), c.DisplayPath(path), counts))
		}
		return code, nil
	},
}

var getCommand = command{
	name:     "get",
	args:     "<NAME>",
	summary:  "Print a decrypted value",
	examples: []string{"msecrets get DATABASE_URL", "msecrets get DATABASE_URL --env production"},
	complete: completeFirst(secretNames),
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "get <NAME> [--env NAME]"); err != nil {
			return 0, err
		}
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		identities, err := c.RequireIdentities()
		if err != nil {
			return 0, err
		}
		environment, err := singleEnvironment(c, document, f)
		if err != nil {
			return 0, err
		}
		value, err := core.RevealValue(document, identities, args[0], environment)
		if err != nil {
			return 0, err
		}
		if c.StdoutTTY {
			value += "\n"
		}
		_, err = io.WriteString(c.Stdout, value)
		return 0, err
	},
}

func readValue(c *Context, name string, environments []string, args []string) (string, error) {
	if len(args) > 1 {
		return args[1], nil
	}
	if !c.StdinTTY {
		data, err := io.ReadAll(c.Stdin)
		if err != nil {
			return "", err
		}
		text := strings.TrimSuffix(string(data), "\n")
		if len(text) < len(data) {
			text = strings.TrimSuffix(text, "\r")
		}
		return text, nil
	}
	return c.Ask(fmt.Sprintf("Value for %s (%s): ", name, strings.Join(environments, ", ")), true)
}

var setCommand = command{
	name:    "set",
	args:    "<NAME> [VALUE]",
	summary: "Encrypt and store a value (prompts, or reads stdin, when VALUE is omitted)",
	examples: []string{
		"msecrets set DATABASE_URL                     # prompts; the value is not shown",
		"msecrets set DATABASE_URL --env production",
		"msecrets set API_KEY --all -d \"Payments provider\"",
		"openssl rand -base64 32 | msecrets set SESSION_SECRET",
	},
	options: []option{
		{name: "all", description: "Set the value in every environment the secret applies to"},
		{name: "description", short: "d", takesValue: true, placeholder: "TEXT", description: "Describe the secret"},
	},
	complete: completeFirst(secretNames),
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "set <NAME> [VALUE] [--env NAME]"); err != nil {
			return 0, err
		}
		name := args[0]
		if err := core.RequireName(core.SecretName, name); err != nil {
			return 0, err
		}
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		var environments []string
		switch {
		case f.Bool("all"):
			if existing, ok := document.Secrets.Get(name); ok {
				environments = core.SecretEnvironments(document, existing)
			} else {
				environments = document.Environments.Keys()
			}
		case len(f.List("env")) > 0:
			environments = f.List("env")
		default:
			environment, err := c.Environment(document, "")
			if err != nil {
				return 0, err
			}
			environments = []string{environment}
		}
		for _, environment := range environments {
			if _, err := core.RequireEnvironment(document, environment); err != nil {
				return 0, err
			}
		}
		identities, err := c.RequireIdentities()
		if err != nil {
			return 0, err
		}
		value, err := readValue(c, name, environments, args)
		if err != nil {
			return 0, err
		}
		signers, err := update(c, func(current *core.Document) ([]string, error) {
			var signers []string
			for _, environment := range environments {
				sealed, err := core.SetValue(current, identities, core.SetValueInput{Secret: name, Environment: environment, Value: value, As: c.Options.As})
				if err != nil {
					return nil, err
				}
				if !slices.Contains(signers, sealed.By) {
					signers = append(signers, sealed.By)
				}
			}
			if f.Has("description") {
				return signers, core.DescribeSecret(current, name, f.String("description"))
			}
			return signers, nil
		})
		if err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Set %s in %s (signed by %s)", name, strings.Join(environments, ", "), strings.Join(signers, ", ")))
		return 0, nil
	},
}

var unsetCommand = command{
	name:     "unset",
	args:     "<NAME>",
	summary:  "Remove the value of a secret from an environment",
	examples: []string{"msecrets unset SENTRY_DSN --env development"},
	complete: completeFirst(secretNames),
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "unset <NAME> [--env NAME]"); err != nil {
			return 0, err
		}
		name := args[0]
		removed, err := update(c, func(document *core.Document) ([]string, error) {
			targets := f.List("env")
			if len(targets) == 0 {
				environment, err := c.Environment(document, "")
				if err != nil {
					return nil, err
				}
				targets = []string{environment}
			}
			var removed []string
			for _, environment := range targets {
				done, err := core.UnsetValue(document, name, environment)
				if err != nil {
					return nil, err
				}
				if done {
					removed = append(removed, environment)
				}
			}
			return removed, nil
		})
		if err != nil {
			return 0, err
		}
		if len(removed) > 0 {
			c.Success(fmt.Sprintf("Removed %s from %s", name, strings.Join(removed, ", ")))
		} else {
			c.Note(name + " had no value there")
		}
		return 0, nil
	},
}

var rmCommand = command{
	name:     "rm",
	args:     "<NAME>",
	summary:  "Delete a secret from every environment",
	examples: []string{"msecrets rm OLD_TOKEN", "msecrets rm OLD_TOKEN --yes   # without asking (scripts, CI)"},
	options:  []option{optYes},
	complete: completeFirst(secretNames),
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "rm <NAME>"); err != nil {
			return 0, err
		}
		name := args[0]
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		if _, err := core.RequireSecret(document, name); err != nil {
			return 0, err
		}
		if err := c.confirmDanger(f.Bool("yes"), fmt.Sprintf("Delete %s from every environment?", name)); err != nil {
			return 0, err
		}
		if _, err := update(c, func(document *core.Document) (any, error) { return nil, core.DeleteSecret(document, name) }); err != nil {
			return 0, err
		}
		c.Success("Deleted " + name)
		return 0, nil
	},
}

var mvCommand = command{
	name:     "mv",
	args:     "<NAME> <NEW_NAME>",
	summary:  "Rename a secret (values are re-signed, not re-encrypted)",
	examples: []string{"msecrets mv DB_URL DATABASE_URL"},
	complete: completeFirst(secretNames),
	run: func(c *Context, args []string, _ flags) (int, error) {
		if err := requireArgs(args, 2, "mv <NAME> <NEW_NAME>"); err != nil {
			return 0, err
		}
		identities, err := c.Identities()
		if err != nil {
			return 0, err
		}
		if _, err := update(c, func(document *core.Document) (any, error) {
			return nil, core.RenameSecret(document, identities, args[0], args[1])
		}); err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Renamed %s to %s", args[0], args[1]))
		return 0, nil
	},
}

var describeCommand = command{
	name:     "describe",
	args:     "<NAME> [TEXT...]",
	summary:  "Set (or, without TEXT, clear) the description of a secret",
	examples: []string{"msecrets describe DATABASE_URL Primary database", "msecrets describe DATABASE_URL   # clears it"},
	complete: completeFirst(secretNames),
	run: func(c *Context, args []string, _ flags) (int, error) {
		if err := requireArgs(args, 1, "describe <NAME> [TEXT...]"); err != nil {
			return 0, err
		}
		text := strings.TrimSpace(strings.Join(args[1:], " "))
		if _, err := update(c, func(document *core.Document) (any, error) {
			return nil, core.DescribeSecret(document, args[0], text)
		}); err != nil {
			return 0, err
		}
		if text != "" {
			c.Success("Described " + args[0])
		} else {
			c.Success("Cleared the description of " + args[0])
		}
		return 0, nil
	},
}

var scopeCommand = command{
	name:     "scope",
	args:     "<NAME> [ENV...]",
	summary:  "Limit a secret to some environments (--all: every environment)",
	examples: []string{"msecrets scope SENTRY_DSN staging production", "msecrets scope SENTRY_DSN --all"},
	options: []option{
		{name: "all", description: "Apply the secret to every environment"},
		optYes,
	},
	complete: completeThen(secretNames, environmentNames),
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "scope <NAME> [ENV...] | --all"); err != nil {
			return 0, err
		}
		name := args[0]
		var environments []string
		if !f.Bool("all") {
			environments = splitCommas(args[1:])
			if len(environments) == 0 {
				return 0, usageError("List environments, or pass --all")
			}
		}
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		secret, err := core.RequireSecret(document, name)
		if err != nil {
			return 0, err
		}
		var dropped []string
		for _, environment := range secret.Values.Keys() {
			if environments != nil && !slices.Contains(environments, environment) {
				dropped = append(dropped, environment)
			}
		}
		if len(dropped) > 0 {
			if err := c.confirmDanger(f.Bool("yes"), fmt.Sprintf("This removes the values of %s in %s. Continue?", name, strings.Join(dropped, ", "))); err != nil {
				return 0, err
			}
		}
		if _, err := update(c, func(document *core.Document) ([]string, error) {
			return core.ScopeSecret(document, name, environments)
		}); err != nil {
			return 0, err
		}
		if environments != nil {
			c.Success(fmt.Sprintf("%s now applies to %s", name, strings.Join(environments, ", ")))
		} else {
			c.Success(name + " now applies to every environment")
		}
		return 0, nil
	},
}
