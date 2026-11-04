package core

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

func reveal(document *Document, identity *Identity, secret, environment string) (string, error) {
	return RevealValue(document, []*Identity{identity}, secret, environment)
}

func cellState(t *testing.T, document *Document, secret, environment string) CellState {
	t.Helper()
	return must[Cell](t)(InspectCell(document, secret, environment)).State
}

func inspectOK(t *testing.T, document *Document) bool {
	t.Helper()
	return must[Report](t)(Inspect(document)).OK
}

func slotNames(slots []Slot, format func(Slot) string) string {
	names := make([]string, len(slots))
	for index, slot := range slots {
		names[index] = format(slot)
	}
	slices.Sort(names)
	return strings.Join(names, ",")
}

func TestMembersReadTheirEnvironments(t *testing.T) {
	document, people := sampleDocument(t)
	equal(t, must[string](t)(reveal(document, people.alice, "DATABASE_URL", "production")), "postgres://prod")
	equal(t, must[string](t)(reveal(document, people.bob, "DATABASE_URL", "development")), "postgres://dev")
	equal(t, must[string](t)(reveal(document, people.ci, "DATABASE_URL", "production")), "postgres://prod")
	_, err := reveal(document, people.bob, "DATABASE_URL", "production")
	expectError(t, err, CodeAccessDenied, "")
	_, err = reveal(document, people.carol, "DATABASE_URL", "development")
	expectError(t, err, CodeAccessDenied, "None of your loaded keys belongs")
}

func TestExactValues(t *testing.T) {
	document, people := sampleDocument(t)
	for _, value := range []string{"", " padded ", "line1\nline2\r\n", "zażółć 🔐", strings.Repeat("x", 200_000)} {
		must[*SealedValue](t)(SetValue(document, []*Identity{people.alice}, SetValueInput{Secret: "EXACT", Environment: "development", Value: value}))
		equal(t, must[string](t)(reveal(copyDocument(t, document), people.bob, "EXACT", "development")), value)
	}
	_, err := SetValue(document, []*Identity{people.alice}, SetValueInput{Secret: "NUL", Environment: "development", Value: "a\x00b"})
	expectError(t, err, CodeUsage, "NUL")
	_, err = SetValue(document, []*Identity{people.alice}, SetValueInput{Secret: "BINARY", Environment: "development", Value: "\xff"})
	expectError(t, err, CodeUsage, "UTF-8")
}

func TestWriters(t *testing.T) {
	document, people := sampleDocument(t)
	_, err := SetValue(document, []*Identity{people.ci}, SetValueInput{Secret: "X", Environment: "production", Value: "1"})
	expectError(t, err, CodeAccessDenied, "signing key")
	_, err = SetValue(document, []*Identity{people.bob}, SetValueInput{Secret: "X", Environment: "production", Value: "1"})
	expectError(t, err, CodeAccessDenied, "")
	_, err = SetValue(document, []*Identity{people.alice}, SetValueInput{Secret: "X", Environment: "production", Value: "1", As: "bob"})
	expectError(t, err, CodeAccessDenied, `"bob" is not`)
}

func TestMovedValuesFailVerification(t *testing.T) {
	document, people := sampleDocument(t)
	secret, _ := document.Secrets.Get("DATABASE_URL")
	production, _ := secret.Values.Get("production")

	moved := copyDocument(t, document)
	must[*SealedValue](t)(SetValue(moved, []*Identity{people.alice}, SetValueInput{Secret: "OTHER", Environment: "production", Value: "x"}))
	other, _ := moved.Secrets.Get("OTHER")
	other.Values.Set("production", production)
	equal(t, cellState(t, moved, "OTHER", "production"), StateInvalid)
	_, err := reveal(moved, people.alice, "OTHER", "production")
	expectError(t, err, CodeSignature, "")

	crossEnvironment := copyDocument(t, document)
	check(t, AddEnvironment(crossEnvironment, "staging", []string{"alice", "ci"}))
	crossSecret, _ := crossEnvironment.Secrets.Get("DATABASE_URL")
	crossSecret.Values.Set("staging", production)
	equal(t, cellState(t, crossEnvironment, "DATABASE_URL", "staging"), StateInvalid)

	otherFile := copyDocument(t, document)
	otherFile.ID = strings.Repeat("0", 32)
	equal(t, cellState(t, otherFile, "DATABASE_URL", "production"), StateInvalid)
}

func value(document *Document, secret, environment string) *SealedValue {
	entry, _ := document.Secrets.Get(secret)
	sealed, _ := entry.Values.Get(environment)
	return sealed
}

func TestTamperingRejectedBeforeDecryption(t *testing.T) {
	document, people := sampleDocument(t)
	tampered := copyDocument(t, document)
	sealed := value(tampered, "DATABASE_URL", "development")
	data := must[[]byte](t)(base64.StdEncoding.DecodeString(sealed.Data))
	data[len(data)-1] ^= 1
	sealed.Data = base64.StdEncoding.EncodeToString(data)
	_, err := reveal(tampered, people.alice, "DATABASE_URL", "development")
	expectError(t, err, CodeSignature, "")

	forged := copyDocument(t, document)
	value(forged, "DATABASE_URL", "production").By = "bob"
	if detail := must[Cell](t)(InspectCell(forged, "DATABASE_URL", "production")).Detail; !strings.Contains(detail, `not a recipient of "production"`) {
		t.Fatal(detail)
	}
}

func TestOutsiderCannotInject(t *testing.T) {
	document, people := sampleDocument(t)
	attacker := must[*Identity](t)(GenerateIdentity(false))
	injected := copyDocument(t, document)
	must[*RecipientEntry](t)(AddRecipient(injected, "mallory", attacker.PublicKey.Token, ""))
	production, _ := injected.Environments.Get("production")
	production.Recipients = append(production.Recipients, "mallory")
	must[*SealedValue](t)(SetValue(injected, []*Identity{attacker}, SetValueInput{Secret: "DATABASE_URL", Environment: "production", Value: "postgres://evil"}))
	value(injected, "DATABASE_URL", "production").By = "alice"
	equal(t, cellState(t, injected, "DATABASE_URL", "production"), StateInvalid)
	_, err := reveal(injected, people.alice, "DATABASE_URL", "production")
	expectError(t, err, CodeSignature, "")
}

func TestGrantAndSync(t *testing.T) {
	document, people := sampleDocument(t)
	must[*RecipientEntry](t)(AddRecipient(document, "carol", people.carol.PublicKey.Token, ""))

	byBob := must[SyncResult](t)(GrantAccess(document, []*Identity{people.bob}, "carol", []string{"development", "production"}))
	equal(t, slotNames(byBob.Updated, func(s Slot) string { return s.Secret + "@" + s.Environment }), "DATABASE_URL@development,DEBUG@development")
	equal(t, len(byBob.Skipped), 1)
	equal(t, byBob.Skipped[0].Environment, "production")
	equal(t, cellState(t, document, "DATABASE_URL", "production"), StateStale)
	equal(t, inspectOK(t, document), false)

	byAlice := must[SyncResult](t)(Sync(document, []*Identity{people.alice}, nil))
	equal(t, len(byAlice.Updated), 1)
	equal(t, inspectOK(t, document), true)
	equal(t, must[string](t)(reveal(document, people.carol, "DATABASE_URL", "production")), "postgres://prod")
}

func TestRevoke(t *testing.T) {
	document, people := sampleDocument(t)
	result := must[RevokeResult](t)(RevokeAccess(document, []*Identity{people.alice}, "bob", []string{"development"}, false))
	secretName := func(s Slot) string { return s.Secret }
	equal(t, slotNames(result.Updated, secretName), "DATABASE_URL,DEBUG")
	equal(t, slotNames(result.Rotate, secretName), "DATABASE_URL,DEBUG")
	_, err := reveal(document, people.bob, "DATABASE_URL", "development")
	expectError(t, err, CodeAccessDenied, "")
	equal(t, value(document, "DEBUG", "development").By, "alice")
	equal(t, inspectOK(t, document), true)
}

func TestRevokeRefusesToPretend(t *testing.T) {
	document, people := sampleDocument(t)
	before := SerializeDocument(document)
	_, err := RevokeAccess(document, []*Identity{people.bob}, "ci", []string{"production"}, false)
	expectError(t, err, CodeAccessDenied, "requires re-encrypting values you cannot decrypt")

	incomplete := must[*Document](t)(ParseDocumentText(before, ""))
	result := must[RevokeResult](t)(RevokeAccess(incomplete, []*Identity{people.bob}, "ci", []string{"production"}, true))
	equal(t, len(result.Skipped), 1)
	equal(t, cellState(t, incomplete, "DATABASE_URL", "production"), StateStale)
}

func TestLastRecipient(t *testing.T) {
	document, people := sampleDocument(t)
	must[RevokeResult](t)(RevokeAccess(document, []*Identity{people.alice}, "ci", []string{"production"}, false))
	_, err := RevokeAccess(document, []*Identity{people.alice}, "alice", []string{"production"}, false)
	expectError(t, err, CodeConflict, "last recipient")
}

func TestRemoveRecipient(t *testing.T) {
	document, people := sampleDocument(t)
	must[RevokeResult](t)(RemoveRecipient(document, []*Identity{people.alice}, "bob"))
	equal(t, document.Recipients.Has("bob"), false)
	development, _ := document.Environments.Get("development")
	equal(t, slices.Contains(development.Recipients, "bob"), false)
	equal(t, inspectOK(t, copyDocument(t, document)), true)
}

func TestKeyRotation(t *testing.T) {
	document, people := sampleDocument(t)
	replacement := must[*Identity](t)(GenerateIdentity(false))
	_, err := ReplaceRecipientKey(copyDocument(t, document), []*Identity{people.alice}, "alice", replacement.PublicKey.Token)
	expectError(t, err, CodeAccessDenied, "load the new identity too")

	updated := must[[]Slot](t)(ReplaceRecipientKey(document, []*Identity{people.alice, replacement}, "alice", replacement.PublicKey.Token))
	equal(t, len(updated), 3)
	equal(t, inspectOK(t, document), true)
	equal(t, must[string](t)(reveal(document, replacement, "DATABASE_URL", "production")), "postgres://prod")
	_, err = reveal(document, people.alice, "DATABASE_URL", "production")
	expectError(t, err, CodeAccessDenied, "")
	_, err = ReplaceRecipientKey(document, []*Identity{replacement}, "bob", replacement.PublicKey.Token)
	expectError(t, err, CodeConflict, `already belongs to recipient "alice"`)

	// A machine key can be rotated by any member who can read its environments.
	machine := must[*Identity](t)(GenerateIdentity(false))
	must[[]Slot](t)(ReplaceRecipientKey(document, []*Identity{replacement}, "ci", readOnlyToken(t, machine)))
	equal(t, must[string](t)(reveal(document, machine, "DATABASE_URL", "production")), "postgres://prod")
}

func TestRenameRecipient(t *testing.T) {
	document, people := sampleDocument(t)
	check(t, RenameRecipient(document, "alice", "alice.smith"))
	equal(t, inspectOK(t, copyDocument(t, document)), true)
	equal(t, value(document, "DATABASE_URL", "production").By, "alice.smith")
	equal(t, must[string](t)(reveal(document, people.alice, "DATABASE_URL", "production")), "postgres://prod")
	expectError(t, RenameRecipient(document, "bob", "ci"), CodeConflict, "")
}

func TestDuplicateKeysAndNames(t *testing.T) {
	document, people := sampleDocument(t)
	_, err := AddRecipient(document, "alice2", readOnlyToken(t, people.alice), "")
	expectError(t, err, CodeConflict, `already belongs to recipient "alice"`)
	_, err = AddRecipient(document, "Alice", people.carol.PublicKey.Token, "")
	expectError(t, err, CodeUsage, "")
	_, err = AddRecipient(document, "alice", people.carol.PublicKey.Token, "")
	expectError(t, err, CodeConflict, "")
}

func TestPostQuantumEnvironments(t *testing.T) {
	pq := must[*Identity](t)(GenerateIdentity(true))
	document := CreateDocument()
	must[*RecipientEntry](t)(AddRecipient(document, "quantum", pq.PublicKey.Token, ""))
	check(t, AddEnvironment(document, "production", []string{"quantum"}))
	must[*SealedValue](t)(SetValue(document, []*Identity{pq}, SetValueInput{Secret: "KEY", Environment: "production", Value: "safe"}))
	equal(t, must[string](t)(reveal(copyDocument(t, document), pq, "KEY", "production")), "safe")
	equal(t, inspectOK(t, document), true)

	classic := must[*Identity](t)(GenerateIdentity(false))
	must[*RecipientEntry](t)(AddRecipient(document, "classic", classic.PublicKey.Token, ""))
	must[SyncResult](t)(GrantAccess(document, []*Identity{pq}, "classic", []string{"production"}))
	equal(t, must[string](t)(reveal(document, classic, "KEY", "production")), "safe")
	mixed := slices.ContainsFunc(must[Report](t)(Inspect(document)).Findings, func(f Finding) bool {
		return strings.Contains(f.Message, "mixes post-quantum and classical")
	})
	equal(t, mixed, true)
}

func TestRenameSecret(t *testing.T) {
	document, people := sampleDocument(t)
	check(t, RenameSecret(document, []*Identity{people.alice}, "DATABASE_URL", "DB_URL"))
	equal(t, must[string](t)(reveal(document, people.ci, "DB_URL", "production")), "postgres://prod")
	equal(t, inspectOK(t, document), true)

	tampered := copyDocument(t, document)
	value(tampered, "DB_URL", "production").To = strings.Repeat("f", 32)
	expectError(t, RenameSecret(tampered, []*Identity{people.alice}, "DB_URL", "DATABASE_URL"), CodeSignature, "Refusing to re-sign")
}

func TestRenameEnvironment(t *testing.T) {
	document, people := sampleDocument(t)
	check(t, RenameEnvironment(document, []*Identity{people.alice}, "development", "dev"))
	equal(t, strings.Join(document.Environments.Keys(), ","), "dev,production")
	debug, _ := document.Secrets.Get("DEBUG")
	equal(t, strings.Join(debug.Environments, ","), "dev")
	equal(t, inspectOK(t, copyDocument(t, document)), true)
	equal(t, must[string](t)(reveal(document, people.bob, "DEBUG", "dev")), "true")

	other, people := sampleDocument(t)
	expectError(t, RenameEnvironment(other, []*Identity{people.ci}, "production", "prod"), CodeAccessDenied, "")
}

func TestScopes(t *testing.T) {
	document, people := sampleDocument(t)
	equal(t, cellState(t, document, "DEBUG", "production"), StateAbsent)
	check(t, CreateSecret(document, "SENTRY_DSN", "Error reporting", []string{"production"}))
	equal(t, cellState(t, document, "SENTRY_DSN", "production"), StateMissing)
	equal(t, cellState(t, document, "SENTRY_DSN", "development"), StateAbsent)
	_, err := SetValue(document, []*Identity{people.alice}, SetValueInput{Secret: "SENTRY_DSN", Environment: "development", Value: "x"})
	expectError(t, err, CodeUsage, "does not apply")

	equal(t, strings.Join(must[[]string](t)(ScopeSecret(document, "DATABASE_URL", []string{"production"})), ","), "development")
	must[[]string](t)(ScopeSecret(document, "DEBUG", nil))
	equal(t, cellState(t, document, "DEBUG", "production"), StateMissing)
	_, err = ScopeSecret(document, "DEBUG", []string{})
	expectError(t, err, CodeUsage, "at least one environment")
}

func TestAddEnvironmentMakesSecretsMissing(t *testing.T) {
	document, _ := sampleDocument(t)
	check(t, AddEnvironment(document, "staging", []string{"alice"}))
	equal(t, cellState(t, document, "DATABASE_URL", "staging"), StateMissing)
	equal(t, inspectOK(t, document), false)
}

func TestRemoveEnvironment(t *testing.T) {
	document, _ := sampleDocument(t)
	removedValues, removedSecrets, err := RemoveEnvironment(document, "development")
	check(t, err)
	equal(t, strings.Join(removedSecrets, ","), "DEBUG")
	equal(t, len(removedValues), 2)
	equal(t, inspectOK(t, copyDocument(t, document)), true)
}

func TestUnsetDeleteDescribe(t *testing.T) {
	document, _ := sampleDocument(t)
	equal(t, must[bool](t)(UnsetValue(document, "DATABASE_URL", "development")), true)
	equal(t, must[bool](t)(UnsetValue(document, "DATABASE_URL", "development")), false)
	check(t, DescribeSecret(document, "DATABASE_URL", "  Primary database  "))
	secret, _ := document.Secrets.Get("DATABASE_URL")
	equal(t, secret.Description, "Primary database")
	check(t, DescribeSecret(document, "DATABASE_URL", ""))
	equal(t, secret.Description, "")
	check(t, DeleteSecret(document, "DATABASE_URL"))
	expectError(t, DeleteSecret(document, "DATABASE_URL"), CodeNotFound, "")
}

func TestSyncNeverReencryptsInvalidValues(t *testing.T) {
	document, people := sampleDocument(t)
	must[*RecipientEntry](t)(AddRecipient(document, "carol", people.carol.PublicKey.Token, ""))
	development, _ := document.Environments.Get("development")
	development.Recipients = append(development.Recipients, "carol")
	value(document, "DATABASE_URL", "development").Sig = base64.StdEncoding.EncodeToString(make([]byte, 64))
	result := must[SyncResult](t)(Sync(document, []*Identity{people.alice}, nil))
	equal(t, slotNames(result.Updated, func(s Slot) string { return s.Secret }), "DEBUG")
	equal(t, cellState(t, document, "DATABASE_URL", "development"), StateInvalid)
}

func TestEnvironmentWarnings(t *testing.T) {
	document := CreateDocument()
	machine := must[*Identity](t)(GenerateIdentity(false))
	must[*RecipientEntry](t)(AddRecipient(document, "machine", readOnlyToken(t, machine), ""))
	must[*RecipientEntry](t)(AddRecipient(document, "idle", must[*Identity](t)(GenerateIdentity(false)).PublicKey.Token, ""))
	check(t, AddEnvironment(document, "empty", nil))
	check(t, AddEnvironment(document, "readonly", []string{"machine"}))
	report := must[Report](t)(Inspect(document))
	var messages []string
	for _, finding := range report.Findings {
		messages = append(messages, finding.Message)
	}
	all := strings.Join(messages, "\n")
	for _, expected := range []string{`"empty" has no recipients`, `Nobody can write to "readonly"`, `"idle" has no access`} {
		if !strings.Contains(all, expected) {
			t.Error(expected)
		}
	}
	equal(t, report.OK, true)
}
