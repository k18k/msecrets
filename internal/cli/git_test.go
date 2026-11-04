package cli

import (
	"errors"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/k18k/msecrets/internal/core"
)

type team struct{ alice, bob, carol, ci *core.Identity }

func must[T any](t *testing.T) func(T, error) T {
	return func(value T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
}

func setValue(t *testing.T, document *core.Document, signer *core.Identity, secret, environment, value string) {
	t.Helper()
	must[*core.SealedValue](t)(core.SetValue(document, []*core.Identity{signer}, core.SetValueInput{Secret: secret, Environment: environment, Value: value}))
}

// sampleDocument: alice and bob read development, alice and ci (read-only) read production.
func sampleDocument(t *testing.T) (*core.Document, team) {
	t.Helper()
	generate := func() *core.Identity { return must[*core.Identity](t)(core.GenerateIdentity(false)) }
	people := team{generate(), generate(), generate(), generate()}
	document := core.CreateDocument()
	readOnly := must[*core.PublicKey](t)(core.ReadOnlyPublicKey(people.ci.PublicKey))
	must[*core.RecipientEntry](t)(core.AddRecipient(document, "alice", people.alice.PublicKey.Token, ""))
	must[*core.RecipientEntry](t)(core.AddRecipient(document, "bob", people.bob.PublicKey.Token, ""))
	must[*core.RecipientEntry](t)(core.AddRecipient(document, "ci", readOnly.Token, ""))
	if err := errors.Join(core.AddEnvironment(document, "development", []string{"alice", "bob"}), core.AddEnvironment(document, "production", []string{"alice", "ci"})); err != nil {
		t.Fatal(err)
	}
	setValue(t, document, people.alice, "DATABASE_URL", "development", "postgres://dev")
	setValue(t, document, people.alice, "DATABASE_URL", "production", "postgres://prod")
	setValue(t, document, people.bob, "DEBUG", "development", "true")
	must[[]string](t)(core.ScopeSecret(document, "DEBUG", []string{"development"}))
	return document, people
}

func text(document *core.Document) string { return core.SerializeDocument(document) }

func fork(t *testing.T, document *core.Document) *core.Document {
	return must[*core.Document](t)(core.ParseDocumentText(text(document), ""))
}

func reveal(t *testing.T, document *core.Document, identity *core.Identity, secret, environment string) string {
	t.Helper()
	return must[string](t)(core.RevealValue(document, []*core.Identity{identity}, secret, environment))
}

func TestTextconvRendering(t *testing.T) {
	document, _ := sampleDocument(t)
	rendered := renderForDiff(text(document))
	for _, pattern := range []string{
		`(?m)^# msecrets file [0-9a-f]{32}$`, `(?m)^ {2}ci: x25519 \(read-only\) [0-9a-f]{12}$`, `(?m)^ {2}production: alice, ci$`,
		`(?m)^ {4}production: signed by alice [0-9a-f]{12}$`, `(?m)^ {4}only: development$`,
	} {
		expectMatch(t, rendered, pattern)
	}
	if strings.Contains(rendered, "YWdl") {
		t.Fatal("ciphertext in the rendering")
	}
	expectMatch(t, renderForDiff("{}"), `^# msecrets: this file is not a valid v4 secrets file`)
}

func TestTextconvChangedAndForgedValues(t *testing.T) {
	document, people := sampleDocument(t)
	before := strings.Split(renderForDiff(text(document)), "\n")
	changed := fork(t, document)
	setValue(t, changed, people.alice, "DATABASE_URL", "production", "postgres://new")
	var differences []string
	for index, line := range strings.Split(renderForDiff(text(changed)), "\n") {
		if line != before[index] {
			differences = append(differences, line)
		}
	}
	if len(differences) != 1 || !strings.Contains(differences[0], "production: signed by alice") {
		t.Fatal(differences)
	}

	forged := fork(t, document)
	secret, _ := forged.Secrets.Get("DATABASE_URL")
	value, _ := secret.Values.Get("production")
	value.By = "ci"
	expectMatch(t, renderForDiff(text(forged)), `production: INVALID SIGNATURE by ci`)
}

func TestMergeIndependentChanges(t *testing.T) {
	base, people := sampleDocument(t)
	ours, theirs := fork(t, base), fork(t, base)
	setValue(t, ours, people.alice, "OURS", "development", "a")
	setValue(t, theirs, people.bob, "THEIRS", "development", "b")
	setValue(t, theirs, people.alice, "DATABASE_URL", "production", "changed")
	merged, conflicts := mergeDocuments(text(base), text(ours), text(theirs))
	if len(conflicts) > 0 {
		t.Fatal(conflicts)
	}
	document := must[*core.Document](t)(core.ParseDocumentText(merged, ""))
	if reveal(t, document, people.alice, "OURS", "development") != "a" || reveal(t, document, people.alice, "THEIRS", "development") != "b" ||
		reveal(t, document, people.alice, "DATABASE_URL", "production") != "changed" {
		t.Fatal("values lost")
	}
	report := must[core.Report](t)(core.Inspect(document))
	for _, cell := range report.Cells {
		if cell.State == core.StateInvalid || cell.State == core.StateStale {
			t.Fatal(cell)
		}
	}
}

func TestMergeAccessListsAsSets(t *testing.T) {
	base, people := sampleDocument(t)
	ours, theirs := fork(t, base), fork(t, base)
	must[*core.RecipientEntry](t)(core.AddRecipient(ours, "carol", people.carol.PublicKey.Token, ""))
	must[core.SyncResult](t)(core.GrantAccess(ours, []*core.Identity{people.alice}, "carol", []string{"development"}))
	setValue(t, theirs, people.bob, "NEW", "development", "x")
	merged, conflicts := mergeDocuments(text(base), text(ours), text(theirs))
	if len(conflicts) > 0 {
		t.Fatal(conflicts)
	}
	document := must[*core.Document](t)(core.ParseDocumentText(merged, ""))
	development, _ := document.Environments.Get("development")
	if !reflect.DeepEqual(development.Recipients, []string{"alice", "bob", "carol"}) {
		t.Fatal(development.Recipients)
	}
	if must[core.Cell](t)(core.InspectCell(document, "NEW", "development")).State != core.StateStale {
		t.Fatal("values sealed for the old set must become stale")
	}
}

func TestMergeScopeConflicts(t *testing.T) {
	base, _ := sampleDocument(t)
	ours, theirs := fork(t, base), fork(t, base)
	must[[]string](t)(core.ScopeSecret(ours, "DEBUG", nil))
	must[[]string](t)(core.ScopeSecret(theirs, "DEBUG", []string{"production"}))
	merged, conflicts := mergeDocuments(text(base), text(ours), text(theirs))
	if !reflect.DeepEqual(conflicts, []string{"secrets.DEBUG.environments"}) {
		t.Fatal(conflicts)
	}
	document := must[*core.Document](t)(core.ParseDocumentText(merged, ""))
	if debug, _ := document.Secrets.Get("DEBUG"); debug.Environments != nil {
		t.Fatal(debug.Environments)
	}
}

func TestMergeSameValueKeepsOurs(t *testing.T) {
	base, people := sampleDocument(t)
	ours, theirs := fork(t, base), fork(t, base)
	setValue(t, ours, people.alice, "DATABASE_URL", "development", "ours")
	setValue(t, theirs, people.bob, "DATABASE_URL", "development", "theirs")
	merged, conflicts := mergeDocuments(text(base), text(ours), text(theirs))
	if !reflect.DeepEqual(conflicts, []string{"secrets.DATABASE_URL.values.development"}) {
		t.Fatal(conflicts)
	}
	if reveal(t, must[*core.Document](t)(core.ParseDocumentText(merged, "")), people.alice, "DATABASE_URL", "development") != "ours" {
		t.Fatal("ours lost")
	}
}

func TestMergeToInvalidFileIsReported(t *testing.T) {
	base, people := sampleDocument(t)
	ours, theirs := fork(t, base), fork(t, base)
	// Ours removes bob entirely; theirs adds a value signed by bob.
	must[core.RevokeResult](t)(core.RemoveRecipient(ours, []*core.Identity{people.alice}, "bob"))
	must[any](t)(nil, core.DeleteSecret(ours, "DEBUG"))
	setValue(t, theirs, people.bob, "BY_BOB", "development", "x")
	merged, conflicts := mergeDocuments(text(base), text(ours), text(theirs))
	if !slices.ContainsFunc(conflicts, func(c string) bool { return strings.Contains(c, `Unknown recipient "bob"`) }) {
		t.Fatal(conflicts)
	}
	if merged != text(ours) {
		t.Fatal("ours must be kept")
	}
}

func TestMergeHostileKeysAndUnrelatedFiles(t *testing.T) {
	base, _ := sampleDocument(t)
	theirs := strings.Replace(text(base), `"secrets": {`, `"secrets": {"__proto__": {"polluted": true},`, 1)
	if _, conflicts := mergeDocuments(text(base), text(base), theirs); !slices.ContainsFunc(conflicts, func(c string) bool { return strings.Contains(c, "__proto__") }) {
		t.Fatal(conflicts)
	}
	left, _ := sampleDocument(t)
	right, _ := sampleDocument(t)
	if _, conflicts := mergeDocuments("", text(left), text(right)); !slices.Contains(conflicts, "id") {
		t.Fatal(conflicts)
	}
}

// With real git: git setup, a readable diff, and a clean structural merge of two branches.
func TestGitSetupDiffAndMerge(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	ws := newWorkspace(t)
	alice := ws.person("alice")
	gitRun := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=Alice", "-c", "user.email=alice@example.com", "-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = ws.project
		cmd.Env = alice.environ(nil)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, output)
		}
		return string(output)
	}
	gitRun("init", "-q")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"set", "A", "1"}))
	setup := alice.run(t, []string{"git", "setup"})
	ok(t, setup)
	expectMatch(t, readFile(t, filepath.Join(ws.project, ".gitattributes")), `(?m)^msecrets\.json diff=msecrets merge=msecrets$`)
	ok(t, alice.run(t, []string{"git", "setup"})) // idempotent
	if strings.Count(readFile(t, filepath.Join(ws.project, ".gitattributes")), "msecrets.json") != 1 {
		t.Fatal("duplicated attribute")
	}
	gitRun("add", ".")
	gitRun("commit", "-qm", "base")

	ok(t, alice.run(t, []string{"set", "A", "2"}))
	expectMatch(t, gitRun("diff"), `(?m)^[-+] {4}development: signed by alice [0-9a-f]{12}$`)
	gitRun("commit", "-qam", "change A")

	gitRun("checkout", "-qb", "other", "HEAD~1")
	ok(t, alice.run(t, []string{"set", "B", "3"}))
	gitRun("commit", "-qam", "add B")
	gitRun("merge", "-q", "--no-edit", "main")
	if got := alice.run(t, []string{"get", "A"}).stdout; got != "2" {
		t.Fatal(got)
	}
	if got := alice.run(t, []string{"get", "B"}).stdout; got != "3" {
		t.Fatal(got)
	}
	ok(t, alice.run(t, []string{"set", "A", "4", "--env", "production"}))
	ok(t, alice.run(t, []string{"set", "B", "4", "--env", "production"}))
	ok(t, alice.run(t, []string{"check"}))
	if regexp.MustCompile(`<<<<<<<`).MatchString(readFile(t, filepath.Join(ws.project, "msecrets.json"))) {
		t.Fatal("conflict markers")
	}
}
