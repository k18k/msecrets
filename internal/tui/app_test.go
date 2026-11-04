package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/k18k/msecrets/internal/core"
	"github.com/k18k/msecrets/internal/termui"
)

var (
	enter     = tea.KeyPressMsg{Code: tea.KeyEnter}
	esc       = tea.KeyPressMsg{Code: tea.KeyEscape}
	tab       = tea.KeyPressMsg{Code: tea.KeyTab}
	shiftTab  = tea.KeyPressMsg{Code: tea.KeyTab, Mod: tea.ModShift}
	up        = tea.KeyPressMsg{Code: tea.KeyUp}
	down      = tea.KeyPressMsg{Code: tea.KeyDown}
	left      = tea.KeyPressMsg{Code: tea.KeyLeft}
	right     = tea.KeyPressMsg{Code: tea.KeyRight}
	home      = tea.KeyPressMsg{Code: tea.KeyHome}
	end       = tea.KeyPressMsg{Code: tea.KeyEnd}
	pgUp      = tea.KeyPressMsg{Code: tea.KeyPgUp}
	pgDown    = tea.KeyPressMsg{Code: tea.KeyPgDown}
	del       = tea.KeyPressMsg{Code: tea.KeyDelete}
	backspace = tea.KeyPressMsg{Code: tea.KeyBackspace}
	ctrlU     = tea.KeyPressMsg{Code: 'u', Mod: tea.ModCtrl}
)

type fixture struct {
	app   *App
	path  string
	alice *core.Identity
	cmds  []tea.Cmd
}

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func setup(t *testing.T) *fixture {
	t.Helper()
	alice, err := core.GenerateIdentity(false)
	check(t, err)
	document := core.CreateDocument()
	_, err = core.AddRecipient(document, "alice", alice.PublicKey.Token, "")
	check(t, err)
	check(t, core.AddEnvironment(document, "development", []string{"alice"}))
	check(t, core.AddEnvironment(document, "production", []string{"alice"}))
	for _, value := range []core.SetValueInput{
		{Secret: "DATABASE_URL", Environment: "development", Value: "postgres://dev"},
		{Secret: "API_KEY", Environment: "development", Value: "key"},
		{Secret: "API_KEY", Environment: "production", Value: "key"},
	} {
		_, err := core.SetValue(document, []*core.Identity{alice}, value)
		check(t, err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "msecrets.json")
	check(t, core.CreateDocumentFile(core.NativeHost(), path, document))
	return &fixture{app: newApp(t, path, directory, []*core.Identity{alice}, ""), path: path, alice: alice}
}

func newApp(t *testing.T, path, cwd string, identities []*core.Identity, problem string) *App {
	t.Helper()
	app, err := New(Options{Host: core.NativeHost(), Path: path, Cwd: cwd, Identities: identities, Problem: problem,
		Colors: termui.NewColors(false), Symbols: termui.NewSymbols(true)})
	check(t, err)
	return app
}

// feed types keys: strings character by character, key messages as they are.
func (f *fixture) feed(keys ...any) {
	for _, k := range keys {
		switch k := k.(type) {
		case string:
			for _, r := range k {
				f.send(tea.KeyPressMsg{Code: r, Text: string(r)})
			}
		case tea.Msg:
			f.send(k)
		}
	}
}

func (f *fixture) send(msg tea.Msg) {
	if _, cmd := f.app.Update(msg); cmd != nil {
		f.cmds = append(f.cmds, cmd)
	}
}

func (f *fixture) screen() string { return strings.Join(f.app.render(110, 30), "\n") }

func (f *fixture) file(t *testing.T) *core.Document {
	t.Helper()
	document, err := core.ReadDocumentFile(core.NativeHost(), f.path)
	check(t, err)
	return document
}

func (f *fixture) reveal(t *testing.T, secret, environment string) string {
	t.Helper()
	value, err := core.RevealValue(f.file(t), []*core.Identity{f.alice}, secret, environment)
	check(t, err)
	return value
}

func (f *fixture) selectSecret(name string) { f.app.row = slices.Index(f.app.secrets(), name) }

func match(t *testing.T, text, pattern string) {
	t.Helper()
	if !regexp.MustCompile(pattern).MatchString(text) {
		t.Fatalf("%s does not match\n%s", pattern, text)
	}
}

func TestRendersTheMatrix(t *testing.T) {
	f := setup(t)
	screen := f.screen()
	match(t, screen, ` msecrets .*msecrets\.json {2}you: alice`)
	match(t, screen, `1 Secrets .* 2 Environments .* 3 Recipients .* 4 Checks`)
	match(t, screen, `SECRET\s+development\s+production\s+DESCRIPTION`)
	match(t, screen, `› API_KEY\s+\[●\]\s+●`) // the selected cell is bracketed
	match(t, screen, `DATABASE_URL\s+●\s+○`)
	match(t, screen, `1 error\(s\)`)
	match(t, screen, `enter edit · v reveal`)
	for _, line := range f.app.render(110, 30) {
		if ansi.StringWidth(line) > 110 {
			t.Fatal(line)
		}
	}
}

func TestAddASecretThenFillTheMissingCell(t *testing.T) {
	f := setup(t)
	f.feed("aNEW_SECRET", enter, "s3cret", enter)
	if f.app.status.text != "Set NEW_SECRET in development" || f.reveal(t, "NEW_SECRET", "development") != "s3cret" {
		t.Fatal(f.app.status.text)
	}
	f.selectSecret("DATABASE_URL")
	f.feed(right, enter, "postgres://prod", enter)
	if f.reveal(t, "DATABASE_URL", "production") != "postgres://prod" {
		t.Fatal("not set")
	}
}

func TestEditingPrefillsHiddenUntilTab(t *testing.T) {
	f := setup(t)
	f.selectSecret("DATABASE_URL")
	f.feed(enter)
	if !strings.Contains(f.screen(), strings.Repeat("•", len("postgres://dev"))) || strings.Contains(f.screen(), "postgres://dev") {
		t.Fatal(f.screen())
	}
	f.feed(tab)
	if !strings.Contains(f.screen(), "postgres://dev") {
		t.Fatal(f.screen())
	}
	f.feed(backspace, backspace, backspace, "prod", enter)
	if got := f.reveal(t, "DATABASE_URL", "development"); got != "postgres://prod" {
		t.Fatal(got)
	}
}

func TestEditFieldNeverSendsControlCharacters(t *testing.T) {
	f := setup(t)
	hostile := "\x1b]52;c;eA==\a\x1b[2Jx"
	_, err := core.UpdateDocumentFile(core.NativeHost(), f.path, func(d *core.Document) (*core.SealedValue, error) {
		return core.SetValue(d, []*core.Identity{f.alice}, core.SetValueInput{Secret: "DATABASE_URL", Environment: "development", Value: hostile})
	})
	check(t, err)
	check(t, f.app.reload())
	f.selectSecret("DATABASE_URL")
	f.feed(enter, tab)
	screen := f.screen()
	if strings.Contains(screen, "\x1b]") || strings.Contains(screen, "\x1b[2J") {
		t.Fatalf("%q", screen)
	}
	match(t, screen, "�\\]52;c;eA==��\\[2Jx")
	f.feed(enter) // saving unchanged keeps the exact value
	if f.reveal(t, "DATABASE_URL", "development") != hostile {
		t.Fatal("value changed")
	}
}

func TestPasteKeepsMultilineValues(t *testing.T) {
	f := setup(t)
	f.selectSecret("DATABASE_URL")
	f.feed(enter, ctrlU, tea.PasteMsg{Content: "-----BEGIN-----\nline\n-----END-----"}, enter)
	if got := f.reveal(t, "DATABASE_URL", "development"); got != "-----BEGIN-----\nline\n-----END-----" {
		t.Fatalf("%q", got)
	}
}

func TestValueChangedElsewhereIsNotOverwritten(t *testing.T) {
	f := setup(t)
	f.selectSecret("DATABASE_URL")
	f.feed(enter)
	_, err := core.UpdateDocumentFile(core.NativeHost(), f.path, func(d *core.Document) (*core.SealedValue, error) {
		return core.SetValue(d, []*core.Identity{f.alice}, core.SetValueInput{Secret: "DATABASE_URL", Environment: "development", Value: "rotated-elsewhere"})
	})
	check(t, err)
	f.feed(enter)
	if f.app.status.tone != toneError {
		t.Fatal(f.app.status)
	}
	match(t, f.app.status.text, `changed while you were editing it; nothing was saved`)
	if f.reveal(t, "DATABASE_URL", "development") != "rotated-elsewhere" {
		t.Fatal("overwritten")
	}
}

func TestEscapeCancelsWithoutWriting(t *testing.T) {
	f := setup(t)
	before, _ := os.ReadFile(f.path)
	f.feed(enter, "changed", esc)
	after, _ := os.ReadFile(f.path)
	if len(f.app.modals) != 0 || string(before) != string(after) {
		t.Fatal("written")
	}
}

func TestRevealAndCopy(t *testing.T) {
	f := setup(t)
	f.selectSecret("DATABASE_URL")
	f.feed("v")
	match(t, f.screen(), `│ postgres://dev`)
	f.feed("c")
	if len(f.cmds) != 1 || fmt.Sprint(f.cmds[0]()) != "postgres://dev" || len(f.app.modals) != 0 {
		t.Fatal(f.cmds)
	}
}

func TestRevealedValuesCannotInjectEscapes(t *testing.T) {
	f := setup(t)
	_, err := core.UpdateDocumentFile(core.NativeHost(), f.path, func(d *core.Document) (*core.SealedValue, error) {
		return core.SetValue(d, []*core.Identity{f.alice}, core.SetValueInput{Secret: "EVIL", Environment: "development", Value: "a\x1b[2Jb\ac"})
	})
	check(t, err)
	check(t, f.app.reload())
	f.selectSecret("EVIL")
	f.app.column = 0
	f.feed("v")
	if screen := f.screen(); !strings.Contains(screen, "a�[2Jb�c") || strings.Contains(screen, "\x1b[2J") {
		t.Fatalf("%q", screen)
	}
}

func TestRenameDescribeUnsetDelete(t *testing.T) {
	f := setup(t)
	f.selectSecret("API_KEY")
	f.feed("r", ctrlU, "PAYMENT_KEY", enter)
	if !f.file(t).Secrets.Has("PAYMENT_KEY") {
		t.Fatal("not renamed")
	}
	f.selectSecret("PAYMENT_KEY")
	f.feed("DPayments provider", enter)
	if secret, _ := f.file(t).Secrets.Get("PAYMENT_KEY"); secret.Description != "Payments provider" {
		t.Fatal(secret.Description)
	}
	f.feed("uy")
	if secret, _ := f.file(t).Secrets.Get("PAYMENT_KEY"); secret.Values.Has("development") {
		t.Fatal("not unset")
	}
	f.feed("dn")
	if !f.file(t).Secrets.Has("PAYMENT_KEY") {
		t.Fatal("n must cancel")
	}
	f.feed("dy")
	if f.file(t).Secrets.Has("PAYMENT_KEY") {
		t.Fatal("not deleted")
	}
}

func TestInvalidInputChangesNothing(t *testing.T) {
	f := setup(t)
	before, _ := os.ReadFile(f.path)
	f.feed("abad name", enter)
	after, _ := os.ReadFile(f.path)
	if f.app.status.tone != toneError || string(before) != string(after) {
		t.Fatal(f.app.status)
	}
	match(t, f.app.status.text, `Invalid secret name`)
}

func TestFilterHelpNavigationQuit(t *testing.T) {
	f := setup(t)
	f.feed("/data", enter)
	if !slices.Equal(f.app.secrets(), []string{"DATABASE_URL"}) {
		t.Fatal(f.app.secrets())
	}
	match(t, f.screen(), `filter: data`)
	f.feed(esc)
	if len(f.app.secrets()) != 2 {
		t.Fatal(f.app.secrets())
	}
	f.feed(down, down, down)
	if f.app.row != 1 {
		t.Fatal("clamped to the last row", f.app.row)
	}
	f.feed(up, end)
	if f.app.row != 1 {
		t.Fatal(f.app.row)
	}
	f.feed(home)
	if f.app.row != 0 {
		t.Fatal(f.app.row)
	}
	f.feed("?")
	match(t, f.screen(), `Keys`)
	f.feed("x")
	if len(f.app.modals) != 0 {
		t.Fatal("help stays open")
	}
	f.feed("q")
	if !f.app.done || len(f.cmds) == 0 {
		t.Fatal("not done")
	}
}

func TestEnvironmentsAddGrantRevoke(t *testing.T) {
	f := setup(t)
	bob, err := core.GenerateIdentity(false)
	check(t, err)
	f.feed("3abob", enter, bob.PublicKey.Token, enter)
	if !f.file(t).Recipients.Has("bob") {
		t.Fatal("bob not added")
	}
	f.feed("2astaging", enter)
	if staging, _ := f.file(t).Environments.Get("staging"); !slices.Equal(staging.Recipients, []string{"alice"}) {
		t.Fatal(staging.Recipients)
	}
	f.app.row = slices.Index(f.app.environments(), "development")
	f.feed("g", enter)
	if development, _ := f.file(t).Environments.Get("development"); !slices.Equal(development.Recipients, []string{"alice", "bob"}) {
		t.Fatal(development.Recipients)
	}
	if value, err := core.RevealValue(f.file(t), []*core.Identity{bob}, "DATABASE_URL", "development"); err != nil || value != "postgres://dev" {
		t.Fatal(value, err)
	}

	f.feed("x")
	match(t, f.screen(), `Revoke access to development`)
	f.feed(down, enter)
	if development, _ := f.file(t).Environments.Get("development"); !slices.Equal(development.Recipients, []string{"alice"}) {
		t.Fatal(development.Recipients)
	}
	match(t, f.screen(), `could read these and may have copies`)
	f.feed(enter)

	f.feed("4")
	match(t, f.screen(), `has no value in "staging"`)
	finding := f.app.report.Findings[0]
	f.feed(enter)
	if f.app.view != secretsView || f.app.selectedSecret() != finding.Secret || f.app.selectedEnvironment() != finding.Environment {
		t.Fatal(f.app.view, f.app.selectedSecret(), finding)
	}
}

func TestRecipientsView(t *testing.T) {
	f := setup(t)
	bob, err := core.GenerateIdentity(false)
	check(t, err)
	f.feed("3abob", enter, bob.PublicKey.Token, enter)
	f.app.row = slices.Index(f.app.recipients(), "bob")
	f.feed("r", ctrlU, "robert", enter)
	if !f.file(t).Recipients.Has("robert") {
		t.Fatal("not renamed")
	}
	f.app.row = slices.Index(f.app.recipients(), "robert")
	f.feed("DContractor", enter)
	match(t, f.screen(), `robert\s+x25519\s+none\s+Contractor`)

	f.feed("g", down, enter)
	if production, _ := f.file(t).Environments.Get("production"); !slices.Equal(production.Recipients, []string{"alice", "robert"}) {
		t.Fatal(production.Recipients)
	}
	f.feed("x", enter)
	if production, _ := f.file(t).Environments.Get("production"); !slices.Equal(production.Recipients, []string{"alice"}) {
		t.Fatal(production.Recipients)
	}
	f.feed(enter, "x")
	if f.app.status.text != "Nothing to choose for: Revoke robert from" {
		t.Fatal(f.app.status.text)
	}
	f.feed("dy")
	if f.file(t).Recipients.Has("robert") {
		t.Fatal("not removed")
	}
	f.feed(enter)
	match(t, f.screen(), `alice \(you\)`)
}

func TestEnvironmentsRenameRemove(t *testing.T) {
	f := setup(t)
	f.feed("2")
	f.app.row = slices.Index(f.app.environments(), "production")
	f.feed("r", ctrlU, "prod", enter)
	if !slices.Equal(f.file(t).Environments.Keys(), []string{"development", "prod"}) {
		t.Fatal(f.file(t).Environments.Keys())
	}
	f.app.row = slices.Index(f.app.environments(), "prod")
	f.feed("d")
	match(t, f.screen(), `Remove prod\?`)
	f.feed("y")
	if !slices.Equal(f.file(t).Environments.Keys(), []string{"development"}) {
		t.Fatal(f.file(t).Environments.Keys())
	}
	f.feed("g", esc)
	if len(f.app.modals) != 0 {
		t.Fatal("modal open")
	}
}

func TestInputEditing(t *testing.T) {
	f := setup(t)
	f.selectSecret("API_KEY")
	f.feed(enter, ctrlU, "acd", left, left, "b", end, "!", home, del, "X", enter)
	if got := f.reveal(t, "API_KEY", "development"); got != "Xbcd!" {
		t.Fatal(got)
	}
}

func TestTinyAndHugeTerminals(t *testing.T) {
	f := setup(t)
	for _, size := range [][2]int{{20, 5}, {40, 12}, {300, 80}} {
		lines := f.app.render(size[0], size[1])
		if len(lines) != size[1] {
			t.Fatal(size, len(lines))
		}
		for _, line := range lines {
			if ansi.StringWidth(line) > size[0] {
				t.Fatal(size, line)
			}
		}
	}
	f.feed("?")
	if len(f.app.render(30, 8)) != 8 {
		t.Fatal("help overflows")
	}
	f.send(tea.WindowSizeMsg{Width: 50, Height: 10})
	if lines := strings.Split(f.app.View().Content, "\n"); len(lines) != 10 || !f.app.View().AltScreen {
		t.Fatal(len(lines))
	}
}

func TestPageKeysAndViewCycling(t *testing.T) {
	f := setup(t)
	f.feed(pgDown)
	if f.app.row != 1 {
		t.Fatal(f.app.row)
	}
	f.feed(pgUp)
	if f.app.row != 0 {
		t.Fatal(f.app.row)
	}
	f.feed(tab)
	if f.app.view != environmentsView {
		t.Fatal(f.app.view)
	}
	f.feed(shiftTab, shiftTab)
	if f.app.view != checksView {
		t.Fatal(f.app.view)
	}
}

func TestReadOnlyModeExplainsWhy(t *testing.T) {
	f := setup(t)
	readOnly := &fixture{app: newApp(t, f.path, filepath.Dir(f.path), nil, "no identity found (run `msecrets identity new`)"), path: f.path}
	match(t, readOnly.screen(), `Read-only: no identity found`)
	readOnly.feed(enter)
	if readOnly.app.status.tone != toneError {
		t.Fatal(readOnly.app.status)
	}
}

func TestASCIISymbols(t *testing.T) {
	env := func(values map[string]string) func(string) (string, bool) {
		return func(key string) (string, bool) { v, ok := values[key]; return v, ok }
	}
	for _, c := range []struct {
		env      map[string]string
		platform string
		want     bool
	}{
		{nil, "windows", false}, {map[string]string{"WT_SESSION": "1"}, "windows", true},
		{map[string]string{"TERM_PROGRAM": "vscode"}, "windows", true}, {nil, "darwin", true},
		{map[string]string{"TERM": "linux"}, "linux", false},
	} {
		if termui.SupportsUnicode(env(c.env), c.platform) != c.want {
			t.Fatal(c)
		}
	}
	var cells []string
	for _, state := range []core.CellState{core.StateOK, core.StateStale, core.StateMissing, core.StateInvalid, core.StateUnexpected, core.StateAbsent} {
		cells = append(cells, termui.NewSymbols(false).Cell[state])
	}
	if strings.Join(cells, "") != "+~-x!." {
		t.Fatal(cells)
	}
}

func TestFit(t *testing.T) {
	for input, want := range map[string]string{"abc": "abc  ", "abcdef": "abc…\x1b[0m", "\x1b[31mabcdef\x1b[39m": "\x1b[31mabc…\x1b[39m\x1b[0m"} {
		width := 5
		if input != "abc" {
			width = 4
		}
		if got := termui.Fit(input, width); got != want {
			t.Fatalf("%q: %q, want %q", input, got, want)
		}
	}
}
