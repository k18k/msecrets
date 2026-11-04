// Package tui is the full-screen terminal UI: a secret × environment matrix,
// environments, recipients, and checks, with keys to change all of them. It
// only calls core; bubbletea runs it.
package tui

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/k18k/msecrets/internal/core"
	"github.com/k18k/msecrets/internal/termui"
)

type view int

const (
	secretsView view = iota
	environmentsView
	recipientsView
	checksView
)

var viewTitles = []string{"Secrets", "Environments", "Recipients", "Checks"}

type modalKind int

const (
	inputModal modalKind = iota
	confirmModal
	messageModal
	pickModal
	helpModal
)

type modal struct {
	kind  modalKind
	title string
	// input
	hint             string
	value            []rune
	cursor           int
	hidden, revealed bool
	submit           func(string) error
	// confirm and message
	lines  []string
	accept func() error
	copy   *string
	// pick
	options []string
	index   int
}

type tone int

const (
	toneInfo tone = iota
	toneSuccess
	toneError
)

type status struct {
	text string
	tone tone
}

var helpRows = [][2]string{
	{"1-4, tab", "switch view"},
	{"↑↓ ←→, hjkl", "move"},
	{"enter, e", "edit the selected value"},
	{"v", "reveal the selected value (c copies it)"},
	{"a", "add (secret, environment, or recipient)"},
	{"r", "rename"},
	{"d", "delete / remove"},
	{"u", "unset the selected value"},
	{"D", "describe"},
	{"g / x", "grant / revoke access"},
	{"s", "sync: re-encrypt for current recipients"},
	{"/", "filter secrets"},
	{"q, ctrl-c", "quit"},
}

// Options configure the UI.
type Options struct {
	Host core.Host
	// Path is the secrets file; Cwd shows it relative.
	Path, Cwd  string
	Identities []*core.Identity
	// Problem explains why there are no identities (read-only mode).
	Problem string
	Colors  termui.Colors
	Symbols termui.Symbols
}

// App is the state of the UI (a bubbletea model).
type App struct {
	Options
	document *core.Document
	report   core.Report
	view     view
	row      int
	column   int
	scroll   int
	filter   string
	modals   []*modal
	status   *status
	done     bool
	width    int
	height   int
	// pending is a command for bubbletea (the clipboard) produced by a key.
	pending tea.Cmd
}

// New reads the secrets file and returns the UI on its first view.
func New(options Options) (*App, error) {
	app := &App{Options: options, width: 80, height: 24}
	if err := app.reload(); err != nil {
		return nil, err
	}
	if options.Problem != "" {
		app.status = &status{"Read-only: " + options.Problem, toneError}
	}
	return app, nil
}

// Data

func (a *App) reload() error {
	document, err := core.ReadDocumentFile(a.Host, a.Path)
	if err != nil {
		return err
	}
	report, err := core.Inspect(document)
	if err != nil {
		return err
	}
	a.document, a.report = document, report
	a.row = max(0, min(a.row, a.rowCount()-1))
	a.column = max(0, min(a.column, len(a.environments())-1))
	return nil
}

func (a *App) environments() []string { return a.document.Environments.Keys() }
func (a *App) recipients() []string   { return a.document.Recipients.Keys() }

func (a *App) secrets() []string {
	filter := strings.ToLower(a.filter)
	var names []string
	for _, name := range a.document.Secrets.Keys() {
		if strings.Contains(strings.ToLower(name), filter) {
			names = append(names, name)
		}
	}
	return names
}

func (a *App) mine() []string {
	members, _ := core.Members(a.document, a.Identities)
	names := make([]string, len(members))
	for index, member := range members {
		names[index] = member.Name
	}
	return names
}

func (a *App) rowCount() int {
	switch a.view {
	case secretsView:
		return len(a.secrets())
	case environmentsView:
		return len(a.environments())
	case recipientsView:
		return len(a.recipients())
	}
	return len(a.report.Findings)
}

func (a *App) cell(secret, environment string) core.CellState {
	for _, cell := range a.report.Cells {
		if cell.Secret == secret && cell.Environment == environment {
			return cell.State
		}
	}
	return core.StateAbsent
}

func at(list []string, index int) string {
	if index >= 0 && index < len(list) {
		return list[index]
	}
	return ""
}

func (a *App) selectedSecret() string { return at(a.secrets(), a.row) }

func (a *App) selectedEnvironment() string {
	if a.view == environmentsView {
		return at(a.environments(), a.row)
	}
	return at(a.environments(), a.column)
}

func (a *App) selectedRecipient() string { return at(a.recipients(), a.row) }

func (a *App) recipientsOf(environment string) []string {
	if entry, ok := a.document.Environments.Get(environment); ok {
		return entry.Recipients
	}
	return nil
}

// mutate changes the file (locked, validated, atomic), then reloads it.
func mutate[T any](a *App, change func(*core.Document) (T, error)) (T, error) {
	result, err := core.UpdateDocumentFile(a.Host, a.Path, change)
	if err != nil {
		return result, err
	}
	return result, a.reload()
}

func (a *App) requireIdentities() ([]*core.Identity, error) {
	if len(a.Identities) == 0 {
		if a.Problem != "" {
			return nil, errors.New(a.Problem)
		}
		return nil, errors.New("No identity loaded; run `msecrets identity new` first")
	}
	return a.Identities, nil
}

// Feedback

func (a *App) succeed(text string) { a.status = &status{text, toneSuccess} }

func (a *App) fail(err error) {
	lines := strings.Split(err.Error(), "\n")
	for index := range lines {
		lines[index] = termui.Sanitize(lines[index])
	}
	if len(lines) > 1 {
		a.modals = append(a.modals, &modal{kind: messageModal, title: "Error", lines: lines})
	}
	a.status = &status{lines[0], toneError}
}

func (a *App) reportSync(result core.SyncResult, prefix string) {
	lines := []string{fmt.Sprintf("%s%d value(s) re-encrypted for the current recipients.", prefix, len(result.Updated))}
	if len(result.Skipped) > 0 {
		lines = append(lines, "", fmt.Sprintf("%d value(s) need a member with access to run sync:", len(result.Skipped)))
		for _, slot := range result.Skipped {
			lines = append(lines, fmt.Sprintf("  %s in %s", slot.Secret, slot.Environment))
		}
		a.modals = append(a.modals, &modal{kind: messageModal, title: "Sync", lines: lines})
	}
	a.succeed(lines[0])
}

func (a *App) reportRevoke(recipient string, result core.RevokeResult) {
	lines := []string{fmt.Sprintf("%d value(s) re-encrypted without \"%s\".", len(result.Updated), recipient)}
	var secrets []string
	for _, slot := range result.Rotate {
		entry := fmt.Sprintf("  %s (%s)", slot.Secret, slot.Environment)
		if !slices.Contains(secrets, entry) {
			secrets = append(secrets, entry)
		}
	}
	if len(secrets) > 0 {
		lines = append(lines, "", fmt.Sprintf("\"%s\" could read these and may have copies. Rotate them:", recipient))
		lines = append(lines, secrets...)
	}
	a.modals = append(a.modals, &modal{kind: messageModal, title: "Access revoked", lines: lines})
	a.succeed(fmt.Sprintf("Revoked \"%s\"", recipient))
}

func (a *App) input(title, hint, value string, hidden bool, submit func(string) error) {
	runes := []rune(value)
	a.modals = append(a.modals, &modal{kind: inputModal, title: title, hint: hint, value: runes, cursor: len(runes), hidden: hidden, submit: submit})
}

func (a *App) confirm(title string, lines []string, accept func() error) {
	a.modals = append(a.modals, &modal{kind: confirmModal, title: title, lines: lines, accept: accept})
}

func (a *App) pick(title string, options []string, submit func(string) error) {
	if len(options) == 0 {
		a.status = &status{"Nothing to choose for: " + title, toneInfo}
		return
	}
	a.modals = append(a.modals, &modal{kind: pickModal, title: title, options: options, submit: submit})
}

// Input handling

// key is a key press: "char" with its text, or a key name ("enter", "ctrl+c", …).
type key struct{ name, text string }

func keyOf(msg tea.KeyPressMsg) key {
	if msg.Text != "" && msg.Mod&^tea.ModShift == 0 {
		return key{"char", msg.Text}
	}
	return key{msg.Keystroke(), ""}
}

// Init implements tea.Model.
func (a *App) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
	case tea.KeyPressMsg:
		a.handle(keyOf(msg))
	case tea.PasteMsg:
		// Pasted text goes into a form verbatim (multi-line values, such as PEM keys, included).
		if top := a.top(); top != nil && top.kind == inputModal {
			paste := []rune(msg.Content)
			top.value = slices.Insert(top.value, top.cursor, paste...)
			top.cursor += len(paste)
		}
	}
	if a.done {
		return a, tea.Quit
	}
	cmd := a.pending
	a.pending = nil
	return a, cmd
}

// View implements tea.Model.
func (a *App) View() tea.View {
	v := tea.NewView(strings.Join(a.render(a.width, a.height), "\n"))
	v.AltScreen = true
	return v
}

func (a *App) top() *modal {
	if len(a.modals) == 0 {
		return nil
	}
	return a.modals[len(a.modals)-1]
}

func (a *App) handle(k key) {
	var err error
	if top := a.top(); top != nil {
		err = a.handleModal(top, k)
	} else {
		err = a.handleView(k)
	}
	if err != nil {
		a.fail(err)
	}
}

func (a *App) closeModal() { a.modals = a.modals[:len(a.modals)-1] }

func (a *App) handleModal(m *modal, k key) error {
	if k.name == "ctrl+c" {
		a.modals = nil
		return nil
	}
	switch m.kind {
	case helpModal:
		a.closeModal()
	case messageModal:
		if k.name == "char" && k.text == "c" && m.copy != nil {
			// OSC 52: most terminals put this on the system clipboard.
			a.pending = tea.SetClipboard(*m.copy)
			a.succeed("Copied to the clipboard (if your terminal supports OSC 52)")
		}
		a.closeModal()
	case confirmModal:
		switch {
		case k.name == "char" && (k.text == "y" || k.text == "Y"):
			a.closeModal()
			return m.accept()
		case k.name == "esc" || k.name == "enter" || (k.name == "char" && (k.text == "n" || k.text == "N")):
			a.closeModal()
		}
	case pickModal:
		switch {
		case k.name == "up" || (k.name == "char" && k.text == "k"):
			m.index = max(0, m.index-1)
		case k.name == "down" || (k.name == "char" && k.text == "j"):
			m.index = min(len(m.options)-1, m.index+1)
		case k.name == "enter":
			a.closeModal()
			return m.submit(m.options[m.index])
		case k.name == "esc":
			a.closeModal()
		}
	case inputModal:
		switch k.name {
		case "enter":
			a.closeModal()
			return m.submit(string(m.value))
		case "esc":
			a.closeModal()
		case "tab":
			m.revealed = !m.revealed
		case "left":
			m.cursor = max(0, m.cursor-1)
		case "right":
			m.cursor = min(len(m.value), m.cursor+1)
		case "home", "ctrl+a":
			m.cursor = 0
		case "end", "ctrl+e":
			m.cursor = len(m.value)
		case "backspace":
			if m.cursor > 0 {
				m.value = slices.Delete(m.value, m.cursor-1, m.cursor)
				m.cursor--
			}
		case "delete":
			if m.cursor < len(m.value) {
				m.value = slices.Delete(m.value, m.cursor, m.cursor+1)
			}
		case "ctrl+u":
			m.value = slices.Delete(m.value, 0, m.cursor)
			m.cursor = 0
		case "char":
			text := []rune(k.text)
			m.value = slices.Insert(m.value, m.cursor, text...)
			m.cursor += len(text)
		}
	}
	return nil
}

func (a *App) handleView(k key) error {
	char := ""
	if k.name == "char" {
		char = k.text
	}
	count := a.rowCount()
	defer func() { a.row = max(0, min(a.row, a.rowCount()-1)) }()

	switch {
	case k.name == "ctrl+c" || char == "q":
		a.done = true
		return nil
	case k.name == "esc" && a.filter != "":
		a.filter = ""
		return a.reload()
	case char == "?":
		a.modals = append(a.modals, &modal{kind: helpModal})
		return nil
	case k.name == "tab" || k.name == "shift+tab" || (len(char) == 1 && char >= "1" && char <= "4"):
		next := (int(a.view) + 1) % len(viewTitles)
		if k.name == "shift+tab" {
			next = (int(a.view) + len(viewTitles) - 1) % len(viewTitles)
		} else if char != "" {
			next = int(char[0] - '1')
		}
		a.view, a.row, a.scroll, a.status = view(next), 0, 0, nil
		return nil
	case k.name == "up" || char == "k":
		a.row = max(0, a.row-1)
	case k.name == "down" || char == "j":
		a.row = min(count-1, a.row+1)
	case k.name == "pgup":
		a.row = max(0, a.row-10)
	case k.name == "pgdown":
		a.row = max(0, min(count-1, a.row+10))
	case k.name == "home":
		a.row = 0
	case k.name == "end":
		a.row = max(0, count-1)
	case a.view == secretsView:
		return a.handleSecretsKey(k, char)
	case a.view == environmentsView:
		return a.handleEnvironmentsKey(char)
	case a.view == recipientsView:
		return a.handleRecipientsKey(char)
	case char == "s":
		return a.runSync()
	case k.name == "enter":
		a.jumpToFinding()
	}
	return nil
}

func (a *App) runSync() error {
	identities, err := a.requireIdentities()
	if err != nil {
		return err
	}
	result, err := mutate(a, func(d *core.Document) (core.SyncResult, error) { return core.Sync(d, identities, nil) })
	if err != nil {
		return err
	}
	a.reportSync(result, "")
	return nil
}

func (a *App) jumpToFinding() {
	if a.row >= len(a.report.Findings) {
		return
	}
	finding := a.report.Findings[a.row]
	switch {
	case finding.Secret != "":
		a.view, a.filter = secretsView, ""
		a.row = max(0, slices.Index(a.secrets(), finding.Secret))
		a.column = max(0, slices.Index(a.environments(), finding.Environment))
	case finding.Environment != "":
		a.view = environmentsView
		a.row = max(0, slices.Index(a.environments(), finding.Environment))
	case finding.Recipient != "":
		a.view = recipientsView
		a.row = max(0, slices.Index(a.recipients(), finding.Recipient))
	}
}

func valueOf(document *core.Document, secret, environment string) *core.SealedValue {
	if entry, ok := document.Secrets.Get(secret); ok {
		value, _ := entry.Values.Get(environment)
		return value
	}
	return nil
}

func (a *App) editValue(secret, environment string) error {
	identities, err := a.requireIdentities()
	if err != nil {
		return err
	}
	original := valueOf(a.document, secret, environment)
	current := ""
	if original != nil {
		// Not readable for us: start from an empty value.
		current, _ = core.RevealValue(a.document, identities, secret, environment)
	}
	a.input(secret+" in "+environment, "enter save · esc cancel · tab show/hide", current, true, func(next string) error {
		if _, err := mutate(a, func(d *core.Document) (*core.SealedValue, error) {
			// The file may have changed since the form opened (another terminal, a git pull).
			if now := valueOf(d, secret, environment); (now == nil) != (original == nil) || (now != nil && now.Data != original.Data) {
				return nil, &core.Error{Code: core.CodeConflict, Message: fmt.Sprintf("%s in %s changed while you were editing it; nothing was saved. Open it again to see the new value", secret, environment)}
			}
			return core.SetValue(d, identities, core.SetValueInput{Secret: secret, Environment: environment, Value: next})
		}); err != nil {
			return err
		}
		a.succeed(fmt.Sprintf("Set %s in %s", secret, environment))
		return nil
	})
	return nil
}

func (a *App) handleSecretsKey(k key, char string) error {
	secret, environment := a.selectedSecret(), a.selectedEnvironment()
	switch {
	case k.name == "left" || char == "h":
		a.column = max(0, a.column-1)
	case k.name == "right" || char == "l":
		a.column = min(len(a.environments())-1, a.column+1)
	case char == "/":
		a.input("Filter secrets", "enter apply · empty clears", a.filter, false, func(value string) error {
			a.filter, a.row = strings.TrimSpace(value), 0
			return nil
		})
	case char == "a":
		a.input("New secret name", "letters, digits, underscores", "", false, func(name string) error {
			name = strings.TrimSpace(name)
			if err := core.RequireName(core.SecretName, name); err != nil {
				return err
			}
			if a.document.Secrets.Has(name) {
				return fmt.Errorf("Secret %s already exists", name)
			}
			target := environment
			if target == "" {
				target = at(a.environments(), 0)
			}
			if target == "" {
				return errors.New("Add an environment first (view 2)")
			}
			return a.editValue(name, target)
		})
	case char == "s":
		return a.runSync()
	case secret == "" || environment == "":
		return nil
	case k.name == "enter" || char == "e":
		return a.editValue(secret, environment)
	case char == "v":
		identities, err := a.requireIdentities()
		if err != nil {
			return err
		}
		value, err := core.RevealValue(a.document, identities, secret, environment)
		if err != nil {
			return err
		}
		var lines []string
		for _, line := range strings.Split(value, "\n") {
			lines = append(lines, termui.Sanitize(line))
		}
		lines = append(lines, "", "c copy · any other key closes")
		a.modals = append(a.modals, &modal{kind: messageModal, title: secret + " in " + environment, lines: lines, copy: &value})
	case char == "r":
		a.input("Rename "+secret, "enter rename · esc cancel", secret, false, func(next string) error {
			next = strings.TrimSpace(next)
			if _, err := mutate(a, func(d *core.Document) (any, error) { return nil, core.RenameSecret(d, a.Identities, secret, next) }); err != nil {
				return err
			}
			a.succeed(fmt.Sprintf("Renamed %s to %s", secret, next))
			return nil
		})
	case char == "d":
		a.confirm("Delete "+secret+"?", []string{"This removes " + secret + " from every environment."}, func() error {
			if _, err := mutate(a, func(d *core.Document) (any, error) { return nil, core.DeleteSecret(d, secret) }); err != nil {
				return err
			}
			a.succeed("Deleted " + secret)
			return nil
		})
	case char == "u":
		a.confirm(fmt.Sprintf("Unset %s in %s?", secret, environment), []string{"The value in " + environment + " will be removed."}, func() error {
			if _, err := mutate(a, func(d *core.Document) (bool, error) { return core.UnsetValue(d, secret, environment) }); err != nil {
				return err
			}
			a.succeed(fmt.Sprintf("Removed %s from %s", secret, environment))
			return nil
		})
	case char == "D":
		entry, _ := a.document.Secrets.Get(secret)
		a.input("Describe "+secret, "empty clears", entry.Description, false, func(text string) error {
			if _, err := mutate(a, func(d *core.Document) (any, error) { return nil, core.DescribeSecret(d, secret, text) }); err != nil {
				return err
			}
			a.succeed("Updated the description of " + secret)
			return nil
		})
	}
	return nil
}

func (a *App) grant(recipient, environment, prefix string) error {
	result, err := mutate(a, func(d *core.Document) (core.SyncResult, error) {
		return core.GrantAccess(d, a.Identities, recipient, []string{environment})
	})
	if err == nil {
		a.reportSync(result, prefix)
	}
	return err
}

func (a *App) revoke(recipient, environment string) error {
	result, err := mutate(a, func(d *core.Document) (core.RevokeResult, error) {
		return core.RevokeAccess(d, a.Identities, recipient, []string{environment}, false)
	})
	if err == nil {
		a.reportRevoke(recipient, result)
	}
	return err
}

func (a *App) handleEnvironmentsKey(char string) error {
	environment := a.selectedEnvironment()
	switch {
	case char == "a":
		a.input("New environment name", "lowercase letters, digits, . _ -", "", false, func(name string) error {
			name = strings.TrimSpace(name)
			recipients := a.mine()
			if _, err := mutate(a, func(d *core.Document) (any, error) { return nil, core.AddEnvironment(d, name, recipients) }); err != nil {
				return err
			}
			a.succeed("Added environment " + name)
			return nil
		})
	case char == "s":
		return a.runSync()
	case environment == "":
		return nil
	case char == "r":
		a.input("Rename "+environment, "enter rename · esc cancel", environment, false, func(next string) error {
			next = strings.TrimSpace(next)
			if _, err := mutate(a, func(d *core.Document) (any, error) {
				return nil, core.RenameEnvironment(d, a.Identities, environment, next)
			}); err != nil {
				return err
			}
			a.succeed(fmt.Sprintf("Renamed %s to %s", environment, next))
			return nil
		})
	case char == "d":
		a.confirm("Remove "+environment+"?", []string{"All values in " + environment + " will be deleted."}, func() error {
			if _, err := mutate(a, func(d *core.Document) (any, error) {
				_, _, err := core.RemoveEnvironment(d, environment)
				return nil, err
			}); err != nil {
				return err
			}
			a.succeed("Removed environment " + environment)
			return nil
		})
	case char == "g":
		current := a.recipientsOf(environment)
		var candidates []string
		for _, name := range a.recipients() {
			if !slices.Contains(current, name) {
				candidates = append(candidates, name)
			}
		}
		a.pick("Grant access to "+environment, candidates, func(recipient string) error {
			return a.grant(recipient, environment, "Granted "+recipient+". ")
		})
	case char == "x":
		a.pick("Revoke access to "+environment, slices.Clone(a.recipientsOf(environment)), func(recipient string) error {
			return a.revoke(recipient, environment)
		})
	}
	return nil
}

func (a *App) handleRecipientsKey(char string) error {
	recipient := a.selectedRecipient()
	switch {
	case char == "a":
		a.input("New recipient name", "lowercase letters, digits, . _ @ + -", "", false, func(name string) error {
			name = strings.TrimSpace(name)
			if err := core.RequireName(core.RecipientName, name); err != nil {
				return err
			}
			a.input("Public key of "+name, "msecrets1…, age1…, or ssh-ed25519 … (paste)", "", false, func(publicKey string) error {
				if _, err := mutate(a, func(d *core.Document) (*core.RecipientEntry, error) {
					return core.AddRecipient(d, name, strings.TrimSpace(publicKey), "")
				}); err != nil {
					return err
				}
				a.succeed("Added " + name + "; grant access with g")
				return nil
			})
			return nil
		})
	case recipient == "":
		return nil
	case char == "r":
		a.input("Rename "+recipient, "enter rename · esc cancel", recipient, false, func(next string) error {
			next = strings.TrimSpace(next)
			if _, err := mutate(a, func(d *core.Document) (any, error) { return nil, core.RenameRecipient(d, recipient, next) }); err != nil {
				return err
			}
			a.succeed(fmt.Sprintf("Renamed %s to %s", recipient, next))
			return nil
		})
	case char == "d":
		a.confirm("Remove "+recipient+"?", []string{"Their access is revoked and values are re-encrypted without them."}, func() error {
			result, err := mutate(a, func(d *core.Document) (core.RevokeResult, error) {
				return core.RemoveRecipient(d, a.Identities, recipient)
			})
			if err == nil {
				a.reportRevoke(recipient, result)
			}
			return err
		})
	case char == "D":
		entry, _ := a.document.Recipients.Get(recipient)
		a.input("Describe "+recipient, "empty clears", entry.Description, false, func(text string) error {
			if _, err := mutate(a, func(d *core.Document) (any, error) { return nil, core.DescribeRecipient(d, recipient, text) }); err != nil {
				return err
			}
			a.succeed("Updated the description of " + recipient)
			return nil
		})
	case char == "g":
		var candidates []string
		for _, name := range a.environments() {
			if !slices.Contains(a.recipientsOf(name), recipient) {
				candidates = append(candidates, name)
			}
		}
		a.pick("Grant "+recipient+" access to", candidates, func(environment string) error {
			return a.grant(recipient, environment, "Granted "+environment+". ")
		})
	case char == "x":
		var candidates []string
		for _, name := range a.environments() {
			if slices.Contains(a.recipientsOf(name), recipient) {
				candidates = append(candidates, name)
			}
		}
		a.pick("Revoke "+recipient+" from", candidates, func(environment string) error {
			return a.revoke(recipient, environment)
		})
	}
	return nil
}

// fileLabel is the secrets file, relative to the working directory when it is inside it.
func (a *App) fileLabel() string {
	relative, err := filepath.Rel(a.Cwd, a.Path)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return a.Path
	}
	return relative
}
