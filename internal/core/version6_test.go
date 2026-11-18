package core

import (
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
)

// asLegacy turns a serialized document into a version 4 file.
func asLegacy(t *testing.T, document *Document) *Map[any] {
	t.Helper()
	input := parseJSONValue(t, SerializeDocument(document))
	input.Set("version", float64(LegacyFormatVersion))
	return input
}

func issuesText(input any) string { return strings.Join(issuesOf(input), "\n") }

func TestVersions(t *testing.T) {
	document, _ := sampleDocument(t)
	text := SerializeDocument(document)
	if !strings.Contains(text, "\n  \"version\": 6,\n") || !strings.Contains(text, "/schema/v6.json") {
		t.Fatal(text)
	}
	// Version 4 files stay readable and are written back as version 6.
	legacy := must[*Document](t)(ParseDocument(asLegacy(t, document), ""))
	equal(t, SerializeDocument(legacy), text)
	if issues := issuesText(parseJSONValue(t, `{"version":7}`)); !strings.Contains(issues, "newer than this msecrets") {
		t.Fatal(issues)
	}
	if issues := issuesText(parseJSONValue(t, `{"version":5}`)); !strings.Contains(issues, "Unsupported format version 5; expected 6") {
		t.Fatal(issues)
	}
}

func TestPlainValues(t *testing.T) {
	document, people := sampleDocument(t)
	alice := []*Identity{people.alice}
	sealed := must[*SealedValue](t)(SetValue(document, alice, SetValueInput{Secret: "API_URL", Environment: "production", Value: "https://api.example.com\n", Plain: true}))
	equal(t, sealed.Plain, true)
	equal(t, sealed.Data, "")

	// Readable without any key, from the file text itself.
	text := SerializeDocument(document)
	if !strings.Contains(text, `"value": "https://api.example.com\n"`) || !strings.Contains(text, `"plain": true`) {
		t.Fatal(text)
	}
	reread := copyDocument(t, document)
	equal(t, must[string](t)(RevealValue(reread, nil, "API_URL", "production")), "https://api.example.com\n")
	equal(t, must[Cell](t)(InspectCell(reread, "API_URL", "production")).State, StateOK)

	// A plain secret stays plain without asking again; an encrypted one is never turned into plain text.
	must[*SealedValue](t)(SetValue(document, alice, SetValueInput{Secret: "API_URL", Environment: "development", Value: "http://localhost"}))
	equal(t, must[string](t)(RevealValue(document, nil, "API_URL", "development")), "http://localhost")
	_, err := SetValue(document, alice, SetValueInput{Secret: "DATABASE_URL", Environment: "development", Value: "x", Plain: true})
	expectError(t, err, CodeUsage, "is an encrypted secret")

	// Writers must still be members: bob cannot write to production.
	_, err = SetValue(document, []*Identity{people.bob}, SetValueInput{Secret: "API_URL", Environment: "production", Value: "evil"})
	expectError(t, err, CodeAccessDenied, "Cannot write")

	// Tampering with the text breaks the signature.
	tampered := copyDocument(t, document)
	value(tampered, "API_URL", "production").Text = "https://evil.example.com"
	equal(t, must[Cell](t)(InspectCell(tampered, "API_URL", "production")).State, StateInvalid)
	_, err = RevealValue(tampered, nil, "API_URL", "production")
	expectError(t, err, CodeSignature, "Refusing")

	// The signature of an encrypted value never verifies a plain value with the same bytes (separate domains).
	encrypted := value(document, "DATABASE_URL", "production")
	forged := copyDocument(t, document)
	value(forged, "API_URL", "production").Sig = encrypted.Sig
	equal(t, must[Cell](t)(InspectCell(forged, "API_URL", "production")).State, StateInvalid)

	// Renames re-sign plain values.
	check(t, RenameSecret(document, alice, "API_URL", "BASE_URL"))
	check(t, RenameEnvironment(document, alice, "production", "prod"))
	equal(t, must[string](t)(RevealValue(copyDocument(t, document), nil, "BASE_URL", "prod")), "https://api.example.com\n")
	equal(t, inspectOK(t, document), true)
}

func TestPlainValueValidation(t *testing.T) {
	document, people := sampleDocument(t)
	must[*SealedValue](t)(SetValue(document, []*Identity{people.alice}, SetValueInput{Secret: "API_URL", Environment: "production", Value: "x", Plain: true}))
	input := parseJSONValue(t, SerializeDocument(document))
	object(input, "secrets", "API_URL", "values", "production").Set("value", "a\x00b")
	object(input, "secrets", "API_URL").Set("plain", false)
	issues := issuesText(input)
	for _, want := range []string{"cannot contain NUL", "Expected true"} {
		if !strings.Contains(issues, want) {
			t.Error(want, issues)
		}
	}
	// A plain value cannot have the shape of an encrypted one, and version 4 has no plain secrets.
	input = parseJSONValue(t, SerializeDocument(document))
	object(input, "secrets", "API_URL", "values", "production").Set("data", "x")
	if !strings.Contains(issuesText(input), "values.production.data: Unknown property") {
		t.Fatal(issuesText(input))
	}
	if !strings.Contains(issuesText(asLegacy(t, document)), "$.secrets.API_URL.plain: Unknown property") {
		t.Fatal(issuesText(asLegacy(t, document)))
	}
}

func TestRevokeKeepsPlainValues(t *testing.T) {
	document, people := sampleDocument(t)
	set := func(signer *Identity, secret string) {
		must[*SealedValue](t)(SetValue(document, []*Identity{signer}, SetValueInput{Secret: secret, Environment: "development", Value: secret, Plain: true}))
	}
	set(people.alice, "BY_ALICE")
	set(people.bob, "BY_BOB")
	before := *value(document, "BY_ALICE", "development")
	result := must[RevokeResult](t)(RevokeAccess(document, []*Identity{people.alice}, "bob", []string{"development"}, false))
	// Public values need no rotation; bob's are re-signed by alice, alice's stay untouched.
	for _, slot := range result.Rotate {
		if strings.HasPrefix(slot.Secret, "BY_") {
			t.Error(slot)
		}
	}
	equal(t, value(document, "BY_BOB", "development").By, "alice")
	equal(t, *value(document, "BY_ALICE", "development"), before)
	for _, secret := range []string{"BY_ALICE", "BY_BOB", "DEBUG"} {
		equal(t, cellState(t, document, secret, "development"), StateOK)
	}
}

func TestPaddingHidesLengths(t *testing.T) {
	document, people := sampleDocument(t)
	alice := []*Identity{people.alice}
	lengths := map[string]int{}
	for _, text := range []string{"", "short", strings.Repeat("x", 63), strings.Repeat("y", 64), "trailing space and newline \n "} {
		sealed := must[*SealedValue](t)(SetValue(document, alice, SetValueInput{Secret: "VALUE", Environment: "development", Value: text}))
		lengths[text] = len(sealed.Data)
		equal(t, must[string](t)(RevealValue(document, alice, "VALUE", "development")), text)
	}
	// Up to 63 bytes, every value has the same ciphertext length; 64 bytes moves to the next bucket.
	equal(t, lengths["short"], lengths[""])
	equal(t, lengths[strings.Repeat("x", 63)], lengths[""])
	equal(t, lengths["trailing space and newline \n "], lengths[""])
	if lengths[strings.Repeat("y", 64)] <= lengths[""] {
		t.Fatal(lengths)
	}
	equal(t, paddedSize(0), 64)
	equal(t, paddedSize(63), 64)
	equal(t, paddedSize(64), 128)
	equal(t, paddedSize(1000), 1024)
}

// sealRaw stores payload as the encrypted value of DATABASE_URL in development, signed by alice,
// as another implementation (or msecrets 5 and earlier) would.
func sealRaw(t *testing.T, document *Document, people team, payload string) {
	t.Helper()
	keys := must[[]*PublicKey](t)(environmentKeys(document, "development"))
	recipients := make([]age.Recipient, len(keys))
	for index, key := range keys {
		recipients[index] = key.Recipient
	}
	data := must[[]byte](t)(EncryptAge([]byte(payload), recipients))
	sealed := ResignValue(document, "DATABASE_URL", "development", &SealedValue{To: RecipientDigest(keys), Data: base64.StdEncoding.EncodeToString(data)}, Member{"alice", people.alice})
	secret, _ := document.Secrets.Get("DATABASE_URL")
	secret.Values.Set("development", sealed)
}

func TestUnpaddedAndBadlyPaddedValues(t *testing.T) {
	document, people := sampleDocument(t)
	alice := []*Identity{people.alice}
	sealRaw(t, document, people, "unpadded, from msecrets 5")
	equal(t, must[string](t)(RevealValue(document, alice, "DATABASE_URL", "development")), "unpadded, from msecrets 5")

	for _, payload := range []string{"short\x00", "x\x00" + strings.Repeat("\x00", 61) + "y", "x" + strings.Repeat("\x00", 127)} {
		sealRaw(t, document, people, payload)
		_, err := RevealValue(document, alice, "DATABASE_URL", "development")
		expectError(t, err, CodeAgePayload, "not padded the way msecrets pads values")
	}
}

func TestPasswordMembers(t *testing.T) {
	document, people := sampleDocument(t)
	_, _, err := NewPasswordIdentity("too short", false)
	expectError(t, err, CodeUsage, "at least 16 characters")

	const password = "correct horse battery staple"
	identity, salt, err := NewPasswordIdentity(password, false)
	check(t, err)
	check(t, AddPasswordRecipient(document, "dana", identity, salt, "types a password"))
	must[SyncResult](t)(GrantAccess(document, []*Identity{people.alice}, "dana", []string{"development"}))

	// The key comes back from the password and the salt in the file, on any machine.
	reread := copyDocument(t, document)
	equal(t, strings.Join(PasswordMembers(reread), ","), "dana")
	member := must[Member](t)(UnlockPassword(reread, password, ""))
	equal(t, member.Name, "dana")
	equal(t, member.Identity.PublicKey.Token, identity.PublicKey.Token)
	equal(t, must[string](t)(RevealValue(reread, []*Identity{member.Identity}, "DATABASE_URL", "development")), "postgres://dev")
	must[*SealedValue](t)(SetValue(reread, []*Identity{member.Identity}, SetValueInput{Secret: "FROM_DANA", Environment: "development", Value: "hi"}))

	_, err = UnlockPassword(reread, password+"!", "")
	expectError(t, err, CodeAccessDenied, "Wrong password for dana")
	_, err = UnlockPassword(reread, password, "alice")
	expectError(t, err, CodeUsage, "not a password member")

	// A rename keeps the key (the salt is random, not the name); a new password replaces key and salt.
	check(t, RenameRecipient(reread, "dana", "dana.k"))
	member = must[Member](t)(UnlockPassword(reread, password, "dana.k"))
	const next = "an even longer new password"
	newIdentity, newSalt := must2(t)(NewPasswordIdentity(next, false))
	must[[]Slot](t)(ReplaceRecipientKey(reread, []*Identity{member.Identity, newIdentity}, "dana.k", newIdentity.PublicKey.Token, newSalt))
	reread = copyDocument(t, reread)
	_, err = UnlockPassword(reread, password, "")
	expectError(t, err, CodeAccessDenied, "Wrong password")
	member = must[Member](t)(UnlockPassword(reread, next, ""))
	equal(t, must[string](t)(RevealValue(reread, []*Identity{member.Identity}, "FROM_DANA", "development")), "hi")
	equal(t, cellState(t, reread, "DATABASE_URL", "development"), StateOK)
}

func must2(t *testing.T) func(*Identity, string, error) (*Identity, string) {
	return func(identity *Identity, salt string, err error) (*Identity, string) {
		t.Helper()
		check(t, err)
		return identity, salt
	}
}

func TestSaltValidation(t *testing.T) {
	document, _ := sampleDocument(t)
	salt := base64.StdEncoding.EncodeToString(make([]byte, saltSize))
	for _, test := range []struct{ recipient, salt, want string }{
		{"alice", "AAAA", "Expected a base64 16-byte salt"},
		{"alice", salt[:len(salt)-2] + "A=", "Expected a base64 16-byte salt"},
		{"ci", salt, "Password members have an msecrets1… key"},
	} {
		input := parseJSONValue(t, SerializeDocument(document))
		object(input, "recipients", test.recipient).Set("salt", test.salt)
		if !strings.Contains(issuesText(input), test.want) {
			t.Errorf("%+v: %s", test, issuesText(input))
		}
	}
	input := asLegacy(t, document)
	object(input, "recipients", "alice").Set("salt", salt)
	if !strings.Contains(issuesText(input), "$.recipients.alice.salt: Unknown property") {
		t.Fatal(issuesText(input))
	}
}

func TestGeneratedPasswords(t *testing.T) {
	format := regexp.MustCompile(`^[2-9a-km-np-z]{5}(-[2-9a-km-np-z]{5}){3}$`)
	seen := map[string]bool{}
	for range 100 {
		password := GeneratePassword()
		if !format.MatchString(password) || seen[password] || PasswordProblem(password) != "" {
			t.Fatal(password)
		}
		seen[password] = true
	}
	equal(t, PasswordProblem("tab\tinside a long password"), "Passwords must not contain control characters")
}
