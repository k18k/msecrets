package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/k18k/msecrets/internal/core"
)

// decryptEnvironment verifies and decrypts every secret of one environment, or fails
// (an app never starts with half of its secrets).
func decryptEnvironment(c *Context, f flags) (string, []entry, error) {
	document, err := c.Document()
	if err != nil {
		return "", nil, err
	}
	environment, err := singleEnvironment(c, document, f)
	if err != nil {
		return "", nil, err
	}
	var names, missing []string
	for name, secret := range document.Secrets.All() {
		if !slices.Contains(core.SecretEnvironments(document, secret), environment) {
			continue
		}
		names = append(names, name)
		if !secret.Values.Has(environment) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return "", nil, coreError(core.CodeNotFound, "Environment \"%s\" is incomplete; these secrets have no value: %s", environment, strings.Join(missing, ", "))
	}
	if len(names) == 0 {
		return environment, nil, nil
	}
	identities, err := c.Identities()
	if err != nil {
		return "", nil, err
	}
	if len(identities) == 0 {
		return "", nil, coreError(core.CodeIdentitySource, "No msecrets identity found. Set MSECRETS_IDENTITY (or MSECRETS_IDENTITY_FILE / MSECRETS_IDENTITY_SOURCE), mount /run/secrets/msecrets_identity, or run `msecrets init` on a developer machine")
	}
	values := make([]entry, len(names))
	for index, name := range names {
		value, err := core.RevealValue(document, identities, name, environment)
		if err != nil {
			return "", nil, err
		}
		values[index] = entry{name, value}
	}
	return environment, values, nil
}

var runCommandSpec = command{
	name:    "run",
	args:    "[--env NAME] -- <COMMAND> [ARGS...]",
	summary: "Run a command with the secrets of an environment as environment variables",
	examples: []string{
		"msecrets run -- npm start",
		"msecrets run --env production -- ./deploy.sh",
		"msecrets run --override -- python app.py   # secrets replace variables already set",
	},
	options:     []option{{name: "override", description: "Let secrets override variables that are already set"}},
	passthrough: true,
	run: func(c *Context, args []string, f flags) (int, error) {
		if len(args) == 0 {
			return 0, usageError(runUsage)
		}
		environment, values, err := decryptEnvironment(c, f)
		if err != nil {
			return 0, err
		}
		env, err := c.ChildEnv()
		if err != nil {
			return 0, err
		}
		injected := 0
		for _, e := range values {
			if _, set := env[e.Name]; set && !f.Bool("override") {
				continue
			}
			env[e.Name] = e.Value
			injected++
		}
		if c.StderrTTY {
			c.Note(c.Err.Dim(fmt.Sprintf("msecrets: %d secret(s) from \"%s\"", injected, environment)))
		}
		return runCommand(c, args, env)
	},
}

var formats = map[string]func([]entry) (string, error){
	"dotenv":     func(e []entry) (string, error) { return formatDotenv(e), nil },
	"json":       formatJSON,
	"shell":      func(e []entry) (string, error) { return formatShell(e), nil },
	"powershell": func(e []entry) (string, error) { return formatPowerShell(e), nil },
}

var exportCommand = command{
	name:    "export",
	summary: "Print the decrypted environment (dotenv, json, shell, powershell)",
	examples: []string{
		"msecrets export --env production > .env.production",
		"eval \"$(msecrets export --format shell)\"",
	},
	options: []option{{name: "format", takesValue: true, placeholder: "FORMAT", description: "dotenv (default), json, shell, or powershell"}},
	run: func(c *Context, _ []string, f flags) (int, error) {
		format := f.String("format")
		if format == "" {
			format = "dotenv"
		}
		render, ok := formats[format]
		if !ok {
			return 0, usageError("Unknown --format \"%s\"; use dotenv, json, shell, powershell%s", format, core.Suggest(format, []string{"dotenv", "json", "shell", "powershell"}))
		}
		_, values, err := decryptEnvironment(c, f)
		if err != nil {
			return 0, err
		}
		text, err := render(values)
		if err != nil {
			return 0, err
		}
		_, err = io.WriteString(c.Stdout, text)
		return 0, err
	},
}

var importCommand = command{
	name:     "import",
	args:     "<FILE | ->",
	summary:  "Import a dotenv file into an environment",
	examples: []string{"msecrets import .env", "msecrets import .env.production --env production --overwrite", "cat .env | msecrets import -"},
	options:  []option{{name: "overwrite", description: "Replace values that already exist"}},
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "import <FILE | -> [--env NAME]"); err != nil {
			return 0, err
		}
		var data []byte
		var err error
		if args[0] == "-" {
			data, err = io.ReadAll(c.Stdin)
		} else {
			data, err = os.ReadFile(resolve(c, args[0]))
		}
		if err != nil {
			return 0, err
		}
		entries, err := parseDotenv(string(data))
		if err != nil {
			return 0, err
		}
		identities, err := c.RequireIdentities()
		if err != nil {
			return 0, err
		}
		type outcome struct {
			environment    string
			imported, kept []string
		}
		result, err := update(c, func(document *core.Document) (outcome, error) {
			target, err := singleEnvironment(c, document, f)
			if err != nil {
				return outcome{}, err
			}
			result := outcome{environment: target}
			for _, e := range entries {
				if existing, ok := document.Secrets.Get(e.Name); ok && existing.Values.Has(target) && !f.Bool("overwrite") {
					result.kept = append(result.kept, e.Name)
					continue
				}
				if _, err := core.SetValue(document, identities, core.SetValueInput{Secret: e.Name, Environment: target, Value: e.Value, As: c.Options.As}); err != nil {
					return outcome{}, err
				}
				result.imported = append(result.imported, e.Name)
			}
			return result, nil
		})
		if err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Imported %d secret(s) into \"%s\"", len(result.imported), result.environment))
		if len(result.kept) > 0 {
			c.Note("Kept existing values (use --overwrite to replace): " + strings.Join(result.kept, ", "))
		}
		return 0, nil
	},
}

func resolve(c *Context, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(c.Cwd, path)
}
