package cli

// Hostile pull requests: an attacker controls the whole msecrets.json, including who
// may read and sign. Each scenario pins down what signatures prevent and what only
// review prevents, and that review can see it in `git diff` (msecrets git setup).

import (
	"reflect"
	"strings"
	"testing"

	"github.com/k18k/msecrets/internal/core"
)

// diff lists the lines of the rendering of after that the rendering of before lacks.
func diff(before, after *core.Document) []string {
	old := map[string]bool{}
	for _, line := range strings.Split(renderForDiff(text(before)), "\n") {
		old[line] = true
	}
	var lines []string
	for _, line := range strings.Split(renderForDiff(text(after)), "\n") {
		if !old[line] {
			lines = append(lines, line)
		}
	}
	return lines
}

// diffFingerprint is the fingerprint the diff shows for a recipient.
func diffFingerprint(document *core.Document, name string) string {
	for _, line := range strings.Split(renderForDiff(text(document)), "\n") {
		if strings.HasPrefix(line, "  "+name+": ") {
			return line[strings.LastIndex(line, " ")+1:]
		}
	}
	return ""
}

func cellOf(t *testing.T, document *core.Document, secret, environment string) core.CellState {
	return must[core.Cell](t)(core.InspectCell(document, secret, environment)).State
}

func reportOK(t *testing.T, document *core.Document) bool {
	return must[core.Report](t)(core.Inspect(document)).OK
}

func TestHostileAddingYourself(t *testing.T) {
	document, people := sampleDocument(t)
	mallory := must[*core.Identity](t)(core.GenerateIdentity(false))
	attack := fork(t, document)
	attack.Recipients.Set("mallory", &core.RecipientEntry{Key: mallory.PublicKey.Token})
	production, _ := attack.Environments.Get("production")
	production.Recipients = append(production.Recipients, "mallory")

	if _, err := core.RevealValue(attack, []*core.Identity{mallory}, "DATABASE_URL", "production"); !core.IsError(err, core.CodeAccessDenied) {
		t.Fatal(err)
	}
	if cellOf(t, attack, "DATABASE_URL", "production") != core.StateStale || reportOK(t, attack) {
		t.Fatal("msecrets check must fail until a member syncs")
	}
	changes := diff(document, attack)
	if !reflect.DeepEqual(changes[:2], []string{"  mallory: x25519 " + diffFingerprint(attack, "mallory"), "  production: alice, ci, mallory"}) || len(changes) != 3 {
		t.Fatal(changes)
	}
	expectMatch(t, changes[2], `^ {4}production: signed, needs sync by alice [0-9a-f]{12}$`)

	// The only step that grants access: a member re-encrypts for the new list. Review must stop it first.
	must[core.SyncResult](t)(core.Sync(attack, []*core.Identity{people.alice}, nil))
	if reveal(t, attack, mallory, "DATABASE_URL", "production") != "postgres://prod" {
		t.Fatal("sync did not grant access")
	}
}

func TestHostileReplacingAKey(t *testing.T) {
	document, _ := sampleDocument(t)
	mallory := must[*core.Identity](t)(core.GenerateIdentity(false))
	attack := fork(t, document)
	alice, _ := attack.Recipients.Get("alice")
	alice.Key = mallory.PublicKey.Token
	if cellOf(t, attack, "DATABASE_URL", "development") != core.StateInvalid || reportOK(t, attack) {
		t.Fatal("values signed with the old key must be invalid")
	}
	// Values written with the replaced key verify: the file cannot tell who "alice" really is.
	setValue(t, attack, mallory, "DATABASE_URL", "production", "postgres://attacker")
	if cellOf(t, attack, "DATABASE_URL", "production") != core.StateOK {
		t.Fatal("expected ok")
	}
	if !strings.Contains(strings.Join(diff(document, attack), "\n"), "  alice: x25519 "+diffFingerprint(attack, "alice")) {
		t.Fatal("the key change must be a visible diff line")
	}
}

func TestHostileRestoringAnOlderValue(t *testing.T) {
	document, people := sampleDocument(t)
	old := fork(t, document)
	setValue(t, document, people.alice, "DATABASE_URL", "production", "postgres://rotated")
	attack := fork(t, document)
	oldSecret, _ := old.Secrets.Get("DATABASE_URL")
	restored, _ := oldSecret.Values.Get("production")
	secret, _ := attack.Secrets.Get("DATABASE_URL")
	secret.Values.Set("production", restored)
	if cellOf(t, attack, "DATABASE_URL", "production") != core.StateOK || reveal(t, attack, people.alice, "DATABASE_URL", "production") != "postgres://prod" {
		t.Fatal("an older signed value verifies")
	}
	changes := diff(document, attack)
	if len(changes) != 1 {
		t.Fatal(changes)
	}
	expectMatch(t, changes[0], `^ {4}production: signed by alice [0-9a-f]{12}$`)
}

func TestHostileForgedMovedReadOnly(t *testing.T) {
	document, people := sampleDocument(t)
	attack := fork(t, document)
	secret, _ := attack.Secrets.Get("DATABASE_URL")
	production, _ := secret.Values.Get("production")
	moved := *production
	secret.Values.Set("development", &moved)
	production.By = "bob"
	if cellOf(t, attack, "DATABASE_URL", "development") != core.StateInvalid || cellOf(t, attack, "DATABASE_URL", "production") != core.StateInvalid {
		t.Fatal("moved and re-attributed values must be invalid")
	}
	if _, err := core.RevealValue(attack, []*core.Identity{people.alice}, "DATABASE_URL", "development"); err == nil {
		t.Fatal("an invalid value was decrypted")
	}
	if _, err := core.SetValue(attack, []*core.Identity{people.ci}, core.SetValueInput{Secret: "X", Environment: "production", Value: "x"}); !core.IsError(err, core.CodeAccessDenied) {
		t.Fatal(err)
	}
}
