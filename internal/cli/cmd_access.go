package cli

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/k18k/msecrets/internal/core"
	"github.com/k18k/msecrets/internal/termui"
)

var envLsCommand = command{
	name:    "env ls",
	summary: "List environments and their recipients",
	run: func(c *Context, _ []string, _ flags) (int, error) {
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		report, err := core.Inspect(document)
		if err != nil {
			return 0, err
		}
		rows := [][]string{{c.Out.Bold("ENVIRONMENT"), c.Out.Bold("VALUES"), c.Out.Bold("RECIPIENTS")}}
		for name, environment := range document.Environments.All() {
			ok, total := 0, 0
			for _, cell := range report.Cells {
				if cell.Environment == name && cell.State != core.StateAbsent {
					total++
					if cell.State == core.StateOK {
						ok++
					}
				}
			}
			recipients := strings.Join(environment.Recipients, ", ")
			if recipients == "" {
				recipients = c.Out.Yellow("none")
			}
			rows = append(rows, []string{name, fmt.Sprintf("%d/%d", ok, total), recipients})
		}
		for _, line := range termui.Table(rows) {
			c.Print(line)
		}
		return 0, nil
	},
}

var envAddCommand = command{
	name:    "env add",
	args:    "<NAME>",
	summary: "Add an environment (recipients: --recipients, --from ENV, or you)",
	examples: []string{
		"msecrets env add staging                 # you are its recipient",
		"msecrets env add staging --from production",
		"msecrets env add preview --recipients alice,ci-preview",
	},
	options: []option{
		{name: "recipients", takesValue: true, multiple: true, placeholder: "LIST", description: "Recipients of the new environment"},
		{name: "from", takesValue: true, placeholder: "ENV", description: "Copy the recipients of another environment"},
	},
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "env add <NAME>"); err != nil {
			return 0, err
		}
		name := args[0]
		identities, err := c.Identities()
		if err != nil {
			return 0, err
		}
		recipients, err := update(c, func(document *core.Document) ([]string, error) {
			var list []string
			switch from, chosen := f.String("from"), f.List("recipients"); {
			case from != "":
				environment, err := core.RequireEnvironment(document, from)
				if err != nil {
					return nil, err
				}
				list = append([]string{}, environment.Recipients...)
			case len(chosen) > 0:
				list = chosen
			default:
				names, err := memberNames(document, identities)
				if err != nil {
					return nil, err
				}
				list = names
			}
			return list, core.AddEnvironment(document, name, list)
		})
		if err != nil {
			return 0, err
		}
		list := strings.Join(recipients, ", ")
		if list == "" {
			list = "none"
		}
		c.Success(fmt.Sprintf("Added environment \"%s\" (recipients: %s)", name, list))
		if len(recipients) == 0 {
			c.Warn("The environment has no recipients yet; add some with `msecrets grant <recipient> " + name + "`")
		}
		return 0, nil
	},
}

var envRmCommand = command{
	name:     "env rm",
	args:     "<NAME>",
	summary:  "Remove an environment and its values",
	options:  []option{optYes},
	complete: completeFirst(environmentNames),
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "env rm <NAME>"); err != nil {
			return 0, err
		}
		name := args[0]
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		if _, err := core.RequireEnvironment(document, name); err != nil {
			return 0, err
		}
		if err := c.confirmDanger(f.Bool("yes"), fmt.Sprintf("Remove environment \"%s\" and all of its values?", name)); err != nil {
			return 0, err
		}
		type removal struct {
			values  []core.Slot
			secrets []string
		}
		result, err := update(c, func(document *core.Document) (removal, error) {
			values, secrets, err := core.RemoveEnvironment(document, name)
			return removal{values, secrets}, err
		})
		if err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Removed environment \"%s\" (%d value(s))", name, len(result.values)))
		if len(result.secrets) > 0 {
			c.Note("Deleted secrets that only applied to it: " + strings.Join(result.secrets, ", "))
		}
		return 0, nil
	},
}

var envMvCommand = command{
	name:     "env mv",
	args:     "<NAME> <NEW_NAME>",
	summary:  "Rename an environment (values are re-signed)",
	examples: []string{"msecrets env mv prod production"},
	complete: completeFirst(environmentNames),
	run: func(c *Context, args []string, _ flags) (int, error) {
		if err := requireArgs(args, 2, "env mv <NAME> <NEW_NAME>"); err != nil {
			return 0, err
		}
		identities, err := c.Identities()
		if err != nil {
			return 0, err
		}
		if _, err := update(c, func(document *core.Document) (any, error) {
			return nil, core.RenameEnvironment(document, identities, args[0], args[1])
		}); err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Renamed environment \"%s\" to \"%s\"", args[0], args[1]))
		return 0, nil
	},
}

var githubUser = regexp.MustCompile(`^github:([A-Za-z0-9-]{1,39})$`)

// resolveKeyArgument resolves github:USER to that user's only ssh-ed25519 key.
func resolveKeyArgument(key string) (string, error) {
	match := githubUser.FindStringSubmatch(key)
	if match == nil {
		return key, nil
	}
	url := "https://github.com/" + match[1] + ".keys"
	client := http.Client{Timeout: 30 * time.Second}
	response, err := client.Get(url)
	if err != nil {
		return "", coreError(core.CodeNotFound, "Could not fetch %s: %v", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", coreError(core.CodeNotFound, "Could not fetch %s: HTTP %d", url, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", coreError(core.CodeNotFound, "Could not fetch %s: %v", url, err)
	}
	var keys []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "ssh-ed25519 ") {
			keys = append(keys, line)
		}
	}
	if len(keys) != 1 {
		return "", usageError("%s has %d ssh-ed25519 keys; pass the one to use explicitly", url, len(keys))
	}
	return keys[0], nil
}

var recipientLsCommand = command{
	name:    "recipient ls",
	summary: "List recipients, their key types, and their access",
	run: func(c *Context, _ []string, _ flags) (int, error) {
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		identities, err := c.Identities()
		if err != nil {
			return 0, err
		}
		mine, err := memberNames(document, identities)
		if err != nil {
			return 0, err
		}
		rows := [][]string{{c.Out.Bold("RECIPIENT"), c.Out.Bold("KEY"), c.Out.Bold("ENVIRONMENTS"), c.Out.Bold("DESCRIPTION")}}
		for name, entry := range document.Recipients.All() {
			key, err := core.RecipientKey(document, name)
			if err != nil {
				return 0, err
			}
			label := name
			if slices.Contains(mine, name) {
				label += c.Out.Cyan(" (you)")
			}
			kind := string(key.Kind)
			if key.SigningKey == nil {
				kind += c.Out.Dim(" read-only")
			}
			environments := strings.Join(environmentsOf(document, name), ", ")
			if environments == "" {
				environments = c.Out.Dim("none")
			}
			rows = append(rows, []string{label, kind, environments, c.Out.Dim(entry.Description)})
		}
		for _, line := range termui.Table(rows) {
			c.Print(line)
		}
		return 0, nil
	},
}

// newKey is the key argument of recipient add/rotate, or a generated read-only machine key.
func newKey(args []string, f flags, missing string) (string, *core.Identity, error) {
	if f.Bool("generate") {
		generated, err := core.GenerateIdentity(f.Bool("pq"))
		if err != nil {
			return "", nil, err
		}
		key, err := core.ReadOnlyPublicKey(generated.PublicKey)
		if err != nil {
			return "", nil, err
		}
		return key.Token, generated, nil
	}
	if len(args) < 2 || args[1] == "" {
		return "", nil, usageError("%s", missing)
	}
	key, err := resolveKeyArgument(strings.Join(args[1:], " "))
	return key, nil, err
}

var recipientAddCommand = command{
	name:    "recipient add",
	args:    "<NAME> [KEY | github:USER]",
	summary: "Add a recipient (person or machine); --generate creates a machine key",
	examples: []string{
		"msecrets recipient add bob msecrets1… --env development",
		"msecrets recipient add carol github:carol",
		"msecrets recipient add ci --generate --env production | gh secret set MSECRETS_IDENTITY",
	},
	options: []option{optGenerate, optPQ,
		{name: "description", short: "d", takesValue: true, placeholder: "TEXT", description: "Describe the recipient"}},
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "recipient add <NAME> <KEY> | --generate"); err != nil {
			return 0, err
		}
		name := args[0]
		key, generated, err := newKey(args, f, "Pass the recipient's public key (msecrets1…, age1…, ssh-ed25519 …, github:USER) or --generate")
		if err != nil {
			return 0, err
		}
		environments := f.List("env")
		var identities []*core.Identity
		if len(environments) > 0 {
			if identities, err = c.Identities(); err != nil {
				return 0, err
			}
		}
		result, err := update(c, func(document *core.Document) (*core.SyncResult, error) {
			if _, err := core.AddRecipient(document, name, key, f.String("description")); err != nil {
				return nil, err
			}
			if len(environments) == 0 {
				return nil, nil
			}
			result, err := core.GrantAccess(document, identities, name, environments)
			return &result, err
		})
		if err != nil {
			return 0, err
		}
		if len(environments) > 0 {
			c.Success(fmt.Sprintf("Added recipient \"%s\" with access to %s", name, strings.Join(environments, ", ")))
			reportSync(c, *result)
		} else {
			c.Success(fmt.Sprintf("Added recipient \"%s\"", name))
		}
		if parsed, err := core.ParsePublicKey(key); err == nil && parsed.SigningKey == nil {
			c.Note(c.Err.Dim("This key cannot sign, so the recipient can read but not write values."))
		}
		if generated != nil {
			fmt.Fprint(c.Stdout, core.FormatIdentityFile(generated, "recipient "+name))
			c.Note(c.Err.Yellow(fmt.Sprintf("The identity above is shown only once. Store it in your runtime secret store and expose it as %s (or mount it at /run/secrets/msecrets_identity).", core.IdentityVariable)))
		}
		return 0, nil
	},
}

var recipientRmCommand = command{
	name:     "recipient rm",
	args:     "<NAME>",
	summary:  "Remove a recipient and re-encrypt everything it could read",
	options:  []option{optYes},
	complete: completeFirst(recipientNames),
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "recipient rm <NAME>"); err != nil {
			return 0, err
		}
		name := args[0]
		document, err := c.Document()
		if err != nil {
			return 0, err
		}
		if _, err := core.RequireRecipient(document, name); err != nil {
			return 0, err
		}
		if err := c.confirmDanger(f.Bool("yes"), fmt.Sprintf("Remove recipient \"%s\"?", name)); err != nil {
			return 0, err
		}
		identities, err := c.Identities()
		if err != nil {
			return 0, err
		}
		result, err := update(c, func(document *core.Document) (core.RevokeResult, error) {
			return core.RemoveRecipient(document, identities, name)
		})
		if err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Removed recipient \"%s\"", name))
		reportRevoke(c, name, result)
		return 0, nil
	},
}

var recipientMvCommand = command{
	name:     "recipient mv",
	args:     "<NAME> <NEW_NAME>",
	summary:  "Rename a recipient",
	complete: completeFirst(recipientNames),
	run: func(c *Context, args []string, _ flags) (int, error) {
		if err := requireArgs(args, 2, "recipient mv <NAME> <NEW_NAME>"); err != nil {
			return 0, err
		}
		if _, err := update(c, func(document *core.Document) (any, error) {
			return nil, core.RenameRecipient(document, args[0], args[1])
		}); err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Renamed recipient \"%s\" to \"%s\"", args[0], args[1]))
		return 0, nil
	},
}

var recipientRotateCommand = command{
	name:    "recipient rotate",
	args:    "<NAME> [NEW_KEY]",
	summary: "Replace a recipient's key and re-encrypt its values (--generate: new machine key)",
	examples: []string{
		"msecrets recipient rotate bob msecrets1…",
		"msecrets recipient rotate ci --generate | gh secret set MSECRETS_IDENTITY",
	},
	options:  []option{optGenerate, optPQ},
	complete: completeFirst(recipientNames),
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 1, "recipient rotate <NAME> <NEW_KEY> | --generate"); err != nil {
			return 0, err
		}
		name := args[0]
		key, generated, err := newKey(args, f, "Pass the new public key or --generate")
		if err != nil {
			return 0, err
		}
		identities, err := c.RequireIdentities()
		if err != nil {
			return 0, err
		}
		updated, err := update(c, func(document *core.Document) ([]core.Slot, error) {
			return core.ReplaceRecipientKey(document, identities, name, key)
		})
		if err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Rotated the key of \"%s\" (%d value(s) re-encrypted)", name, len(updated)))
		if generated != nil {
			fmt.Fprint(c.Stdout, core.FormatIdentityFile(generated, "recipient "+name))
			c.Note(c.Err.Yellow("The identity above is shown only once; replace the old one in your runtime secret store."))
		}
		return 0, nil
	},
}

var grantCommand = command{
	name:     "grant",
	args:     "<RECIPIENT> <ENV...>",
	summary:  "Give a recipient access to environments (re-encrypts their values)",
	examples: []string{"msecrets grant bob development staging"},
	complete: completeThen(recipientNames, environmentNames),
	run: func(c *Context, args []string, _ flags) (int, error) {
		if err := requireArgs(args, 2, "grant <RECIPIENT> <ENV...>"); err != nil {
			return 0, err
		}
		recipient, environments := args[0], args[1:]
		identities, err := c.Identities()
		if err != nil {
			return 0, err
		}
		result, err := update(c, func(document *core.Document) (core.SyncResult, error) {
			return core.GrantAccess(document, identities, recipient, splitCommas(environments))
		})
		if err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Granted \"%s\" access to %s", recipient, strings.Join(environments, ", ")))
		reportSync(c, result)
		return 0, nil
	},
}

var revokeCommand = command{
	name:     "revoke",
	args:     "<RECIPIENT> <ENV...>",
	summary:  "Take away access and re-encrypt the affected values without the recipient",
	examples: []string{"msecrets revoke bob production"},
	options:  []option{{name: "incomplete", description: "Record the revocation even if you cannot re-encrypt every value"}},
	complete: completeThen(recipientNames, environmentNames),
	run: func(c *Context, args []string, f flags) (int, error) {
		if err := requireArgs(args, 2, "revoke <RECIPIENT> <ENV...>"); err != nil {
			return 0, err
		}
		recipient, environments := args[0], args[1:]
		identities, err := c.Identities()
		if err != nil {
			return 0, err
		}
		result, err := update(c, func(document *core.Document) (core.RevokeResult, error) {
			return core.RevokeAccess(document, identities, recipient, splitCommas(environments), f.Bool("incomplete"))
		})
		if err != nil {
			return 0, err
		}
		c.Success(fmt.Sprintf("Revoked \"%s\" from %s", recipient, strings.Join(environments, ", ")))
		reportRevoke(c, recipient, result)
		return 0, nil
	},
}

var syncCommand = command{
	name:     "sync",
	summary:  "Re-encrypt values whose recipients changed",
	examples: []string{"msecrets sync", "msecrets sync --env production"},
	run: func(c *Context, _ []string, f flags) (int, error) {
		identities, err := c.RequireIdentities()
		if err != nil {
			return 0, err
		}
		var environments []string
		if list := f.List("env"); len(list) > 0 {
			environments = list
		}
		result, err := update(c, func(document *core.Document) (core.SyncResult, error) {
			return core.Sync(document, identities, environments)
		})
		if err != nil {
			return 0, err
		}
		if len(result.Updated) == 0 && len(result.Skipped) == 0 {
			c.Success("Everything is up to date")
		}
		reportSync(c, result)
		if len(result.Skipped) > 0 {
			return 1, nil
		}
		return 0, nil
	},
}
