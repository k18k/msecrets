package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/k18k/msecrets/internal/core"
	"github.com/k18k/msecrets/internal/termui"
)

var (
	optYes        = option{name: "yes", short: "y", description: "Do not ask for confirmation"}
	optStore      = option{name: "store", takesValue: true, placeholder: "WHERE", description: "Where to keep a new identity: keychain (default), file, or print"}
	optPQ         = option{name: "pq", description: "Generate a post-quantum (ML-KEM-768 + X25519) key"}
	optPassphrase = option{name: "passphrase", description: "Protect a new identity file with a passphrase"}
	optJSON       = option{name: "json", description: "Machine-readable JSON output"}
	optGenerate   = option{name: "generate", description: "Generate a read-only machine key and print its identity to stdout (for CI / runtime)"}
	optName       = option{name: "name", takesValue: true, placeholder: "NAME", description: "Your recipient name (default: from git user.email)"}
)

// commands lists every command, in help order within each group.
func commands() []command {
	return []command{
		initCommand, joinCommand, whoamiCommand,
		identityNewCommand, identityShowCommand, identityExportCommand, identityUseCommand,
		lsCommand, checkCommand, getCommand, setCommand, unsetCommand, rmCommand, mvCommand, describeCommand, scopeCommand,
		envLsCommand, envAddCommand, envRmCommand, envMvCommand,
		recipientLsCommand, recipientAddCommand, recipientRmCommand, recipientMvCommand, recipientRotateCommand,
		grantCommand, revokeCommand, syncCommand,
		runCommandSpec, exportCommand, importCommand,
		gitSetupCommand, gitTextconvCommand, gitMergeDriverCommand,
		skillCommand,
	}
}

// Completion of names (public data only; failures complete nothing).

func environmentNames(c *Context) []string {
	document, err := c.Document()
	if err != nil {
		return nil
	}
	return document.Environments.Keys()
}

func secretNames(c *Context) []string {
	document, err := c.Document()
	if err != nil {
		return nil
	}
	return document.Secrets.Keys()
}

func recipientNames(c *Context) []string {
	document, err := c.Document()
	if err != nil {
		return nil
	}
	return document.Recipients.Keys()
}

// completeFirst completes the first argument from names, then nothing.
func completeFirst(names func(*Context) []string) func(*Context, []string) []string {
	return func(c *Context, args []string) []string {
		if len(args) == 0 {
			return names(c)
		}
		return nil
	}
}

// completeThen completes the first argument from first, and every other one from rest.
func completeThen(first, rest func(*Context) []string) func(*Context, []string) []string {
	return func(c *Context, args []string) []string {
		if len(args) == 0 {
			return first(c)
		}
		return rest(c)
	}
}

func singleEnvironment(c *Context, document *core.Document, f flags) (string, error) {
	environments := f.List("env")
	if len(environments) > 1 {
		return "", usageError("This command takes a single --env")
	}
	explicit := ""
	if len(environments) == 1 {
		explicit = environments[0]
	}
	return c.Environment(document, explicit)
}

func reportSync(c *Context, result core.SyncResult) {
	if len(result.Updated) > 0 {
		c.Success(fmt.Sprintf("Re-encrypted %d value(s) for the current recipients", len(result.Updated)))
	}
	if len(result.Skipped) > 0 {
		lines := make([]string, len(result.Skipped))
		for index, slot := range result.Skipped {
			lines[index] = fmt.Sprintf("  %s in \"%s\"", slot.Secret, slot.Environment)
		}
		c.Warn(fmt.Sprintf("%d value(s) could not be re-encrypted by you; a member with access must run `msecrets sync`:\n%s", len(result.Skipped), strings.Join(lines, "\n")))
	}
}

func rotateList(slots []core.Slot) []string {
	var list []string
	for _, slot := range slots {
		entry := fmt.Sprintf("%s (%s)", slot.Secret, slot.Environment)
		if !slices.Contains(list, entry) {
			list = append(list, entry)
		}
	}
	return list
}

func reportRevoke(c *Context, recipient string, result core.RevokeResult) {
	reportSync(c, result.SyncResult)
	if len(result.Rotate) > 0 {
		c.Warn(fmt.Sprintf("\"%s\" could read these values and may have kept copies. Rotate them at their source, then `msecrets set` the new values:\n  %s", recipient, strings.Join(rotateList(result.Rotate), "\n  ")))
	}
}

func cellGlyph(c *Context, state core.CellState) string {
	return termui.CellStyle(c.Out, state)(c.Symbols.Cell[state])
}

func printFindings(c *Context, report core.Report) {
	for _, finding := range report.Findings {
		label := c.Out.Yellow("warning")
		if finding.Level == core.LevelError {
			label = c.Out.Red("error")
		}
		c.Print(label + " " + finding.Message)
	}
}

type findingJSON struct {
	Level       core.FindingLevel `json:"level"`
	Message     string            `json:"message"`
	Secret      string            `json:"secret,omitempty"`
	Environment string            `json:"environment,omitempty"`
	Recipient   string            `json:"recipient,omitempty"`
}

func findingsJSON(report core.Report) []findingJSON {
	findings := make([]findingJSON, len(report.Findings))
	for index, f := range report.Findings {
		findings[index] = findingJSON(f)
	}
	return findings
}

func cellState(report core.Report, secret, environment string) core.CellState {
	for _, cell := range report.Cells {
		if cell.Secret == secret && cell.Environment == environment {
			return cell.State
		}
	}
	return core.StateAbsent
}

func environmentsOf(document *core.Document, recipient string) []string {
	var names []string
	for name, environment := range document.Environments.All() {
		if slices.Contains(environment.Recipients, recipient) {
			names = append(names, name)
		}
	}
	return names
}

func memberNames(document *core.Document, identities []*core.Identity) ([]string, error) {
	members, err := core.Members(document, identities)
	names := make([]string, len(members))
	for index, member := range members {
		names[index] = member.Name
	}
	return names, err
}

func splitCommas(args []string) []string {
	var list []string
	for _, arg := range args {
		list = append(list, strings.Split(arg, ",")...)
	}
	return list
}
