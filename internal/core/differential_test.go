package core

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Descriptions that stress JSON serialization differences between Go and JavaScript.
var trickyDescriptions = []string{
	`<script>alert("x") & 'y'</script>`,
	"line separator paragraph",
	`back\slash "quotes" / slash`,
	"emoji 🔐 zażółć nbsp​invisible",
	strings.Repeat("🔐", 500), // exactly 1000 UTF-16 code units
}

func revealAll(t *testing.T, document *Document, identities []*Identity) map[string]string {
	t.Helper()
	values := map[string]string{}
	for secret, entry := range document.Secrets.All() {
		for environment := range entry.Values.All() {
			value, err := RevealValue(document, identities, secret, environment)
			var e *Error
			if errors.As(err, &e) {
				value = "ERROR " + string(e.Code)
			} else if err != nil {
				t.Fatal(err)
			}
			values[secret+"@"+environment] = value
		}
	}
	return values
}

// TestFixtureFromTypeScript loads a file and identities written by the TypeScript implementation.
func TestFixtureFromTypeScript(t *testing.T) {
	directory := filepath.Join("..", "..", "sdk", "test", "fixtures")
	text := string(must[[]byte](t)(os.ReadFile(filepath.Join(directory, "app.ms.json"))))
	document := must[*Document](t)(ParseDocumentText(text, ""))
	equal(t, SerializeDocument(document), text)
	equal(t, inspectOK(t, document), true)

	// Key derivation: the public keys TypeScript wrote into the identity files.
	var identities []*Identity
	for _, name := range []string{"developer", "production"} {
		contents := must[[]byte](t)(os.ReadFile(filepath.Join(directory, name+".identity.txt")))
		parsed := must[[]*Identity](t)(ParseIdentities(contents, IdentityOptions{}))
		if !strings.Contains(string(contents), "# public key: "+parsed[0].PublicKey.Token+"\n") {
			t.Fatalf("%s: public key differs from TypeScript", name)
		}
		identities = append(identities, parsed...)
	}
	values := revealAll(t, document, identities[:1])
	if len(values) == 0 {
		t.Fatal("no values")
	}
	for slot, value := range values {
		if strings.HasPrefix(value, "ERROR") {
			t.Errorf("%s: %s", slot, value)
		}
	}
	// The machine key reads production only.
	for slot, value := range revealAll(t, document, identities[1:]) {
		if strings.HasSuffix(slot, "@production") == strings.HasPrefix(value, "ERROR") {
			t.Errorf("%s: %s", slot, value)
		}
	}
}

// TestGoldenFromTypeScript reads a file the TypeScript implementation (msecrets 4.0) wrote
// with descriptions that stress JSON serialization differences, then modifies it.
func TestGoldenFromTypeScript(t *testing.T) {
	directory := filepath.Join("testdata", "typescript")
	text := string(must[[]byte](t)(os.ReadFile(filepath.Join(directory, DefaultFilename))))
	document := must[*Document](t)(ParseDocumentText(text, ""))
	equal(t, SerializeDocument(document), text)
	equal(t, inspectOK(t, document), true)
	equal(t, strings.Join(document.Environments.Keys(), ","), "2,10,production,development")
	for i, name := range []string{"alice", "bob", "ci"} {
		recipient, _ := document.Recipients.Get(name)
		equal(t, recipient.Description, trickyDescriptions[[]int{0, 1, 4}[i]])
	}
	identities := must[[]*Identity](t)(ParseIdentities(must[[]byte](t)(os.ReadFile(filepath.Join(directory, "identities.txt"))), IdentityOptions{}))
	identities = append(identities, must[*Identity](t)(ParseIdentity(sshFixture(t, "plain"), IdentityOptions{})))
	var want map[string]string
	check(t, json.Unmarshal(must[[]byte](t)(os.ReadFile(filepath.Join(directory, "values.json"))), &want))
	if got := revealAll(t, document, identities); !maps.Equal(got, want) {
		t.Fatalf("values differ:\ngot  %q\nwant %q", got, want)
	}

	// Go modifies the TypeScript-written file and reads it back.
	file := filepath.Join(t.TempDir(), DefaultFilename)
	writeFile(t, file, text)
	must[bool](t)(UpdateDocumentFile(NativeHost(), file, func(document *Document) (bool, error) {
		must[*SealedValue](t)(SetValue(document, identities, SetValueInput{Secret: "FROM_GO", Environment: "2", Value: "go ✓ <&>"}))
		check(t, RenameEnvironment(document, identities, "development", "dev"))
		check(t, RenameRecipient(document, "carol", "carol.ssh"))
		check(t, RenameSecret(document, identities, "DEBUG", "VERBOSE"))
		check(t, DescribeSecret(document, "UNICODE", trickyDescriptions[0]))
		must[RevokeResult](t)(RevokeAccess(document, identities, "ci", []string{"2"}, false))
		return true, nil
	}))
	text = string(must[[]byte](t)(os.ReadFile(file)))
	document = must[*Document](t)(ParseDocumentText(text, ""))
	equal(t, SerializeDocument(document), text)
	values := revealAll(t, document, identities)
	equal(t, values["FROM_GO@2"], "go ✓ <&>")
	equal(t, values["VERBOSE@dev"], "true")
	equal(t, values["UNICODE@2"], want["UNICODE@2"])
}
