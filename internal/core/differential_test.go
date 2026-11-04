package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	directory := filepath.Join("..", "..", "packages", "ts-sdk", "test", "fixtures")
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

type planRecipient struct {
	Name        string `json:"name"`
	Key         string `json:"key"`
	Description string `json:"description,omitempty"`
}

type planEnvironment struct {
	Name       string   `json:"name"`
	Recipients []string `json:"recipients"`
}

type planSecret struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	Environments []string          `json:"environments,omitempty"`
	Values       map[string]string `json:"values"`
}

type plan struct {
	IdentityFiles []string          `json:"identityFiles"`
	Recipients    []planRecipient   `json:"recipients"`
	Environments  []planEnvironment `json:"environments"`
	Secrets       []planSecret      `json:"secrets"`
}

type report struct {
	Canonical    bool              `json:"canonical"`
	Environments []string          `json:"environments"`
	OK           bool              `json:"ok"`
	Values       map[string]string `json:"values"`
}

func runTypeScript(t *testing.T, node, command, file string, p plan) report {
	t.Helper()
	input := must[[]byte](t)(json.Marshal(p))
	cmd := exec.Command(node, filepath.Join("testdata", "differential.ts"), command, file)
	cmd.Stdin = bytes.NewReader(input)
	cmd.Stderr = os.Stderr
	output, err := cmd.Output()
	check(t, err)
	var result report
	check(t, json.Unmarshal(output, &result))
	return result
}

// TestDifferentialWithTypeScript writes files with one implementation and reads them with the other.
func TestDifferentialWithTypeScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not available")
	}
	directory := t.TempDir()
	file := filepath.Join(directory, DefaultFilename)
	alice := must[*Identity](t)(GenerateIdentity(false))
	bob := must[*Identity](t)(GenerateIdentity(true))
	carol := must[*Identity](t)(ParseIdentity(sshFixture(t, "plain"), IdentityOptions{}))
	machine := must[*Identity](t)(GenerateIdentity(false))
	identities := []*Identity{alice, bob, carol, machine}
	keyFile := filepath.Join(directory, "identities.txt")
	writeFile(t, keyFile, FormatIdentityFile(alice, "")+FormatIdentityFile(bob, "")+FormatIdentityFile(machine, ""))
	identityFiles := []string{keyFile, filepath.Join(fixtures, "ssh", "plain")}

	values := map[string]string{
		"DATABASE_URL@development": "postgres://dev",
		"DATABASE_URL@2":           "postgres://two",
		"DATABASE_URL@10":          "postgres://ten",
		"DATABASE_URL@production":  "postgres://prod",
		"DEBUG@development":        "true",
		"EMPTY@production":         "",
		"UNICODE@2":                "zażółć 🔐\n\"\\ <&> ",
	}
	secretValues := func(name string) map[string]string {
		result := map[string]string{}
		for slot, value := range values {
			if secret, environment, _ := strings.Cut(slot, "@"); secret == name {
				result[environment] = value
			}
		}
		return result
	}
	first := plan{
		IdentityFiles: identityFiles,
		Recipients: []planRecipient{
			{"alice", alice.PublicKey.Token, trickyDescriptions[0]},
			{"bob", bob.PublicKey.Token, trickyDescriptions[1]},
			{"carol", carol.PublicKey.Token, ""},
			{"ci", readOnlyToken(t, machine), trickyDescriptions[4]},
		},
		Environments: []planEnvironment{
			{"production", []string{"alice", "ci"}},
			{"development", []string{"carol", "alice"}},
			{"2", []string{"alice", "bob", "ci"}},
			{"10", []string{"alice"}},
		},
		Secrets: []planSecret{
			{"DATABASE_URL", trickyDescriptions[2], nil, secretValues("DATABASE_URL")},
			{"DEBUG", "", []string{"development"}, secretValues("DEBUG")},
			{"EMPTY", trickyDescriptions[3], []string{"production"}, secretValues("EMPTY")},
			{"UNICODE", "", []string{"2"}, secretValues("UNICODE")},
		},
	}

	// TypeScript writes, Go reads.
	created := runTypeScript(t, node, "create", file, first)
	equal(t, created.Canonical, true)
	equal(t, created.OK, true)
	equal(t, strings.Join(created.Environments, ","), "2,10,production,development")
	text := string(must[[]byte](t)(os.ReadFile(file)))
	document := must[*Document](t)(ParseDocumentText(text, ""))
	equal(t, SerializeDocument(document), text)
	equal(t, inspectOK(t, document), true)
	if got := revealAll(t, document, identities); !maps.Equal(got, values) || !maps.Equal(created.Values, values) {
		t.Fatalf("values differ:\nGo  %q\nTS  %q\nwant %q", got, created.Values, values)
	}

	// Go writes, TypeScript reads.
	must[bool](t)(UpdateDocumentFile(NativeHost(), file, func(document *Document) (bool, error) {
		must[*SealedValue](t)(SetValue(document, identities, SetValueInput{Secret: "FROM_GO", Environment: "2", Value: "go ✓ <&>"}))
		check(t, RenameEnvironment(document, identities, "development", "dev"))
		check(t, RenameRecipient(document, "carol", "carol.ssh"))
		check(t, RenameSecret(document, identities, "DEBUG", "VERBOSE"))
		check(t, DescribeSecret(document, "UNICODE", trickyDescriptions[0]))
		must[RevokeResult](t)(RevokeAccess(document, identities, "ci", []string{"2"}, false))
		return true, nil
	}))
	goDocument := must[*Document](t)(ReadDocumentFile(NativeHost(), file))
	checked := runTypeScript(t, node, "check", file, plan{IdentityFiles: identityFiles})
	equal(t, checked.Canonical, true)
	equal(t, checked.OK, inspectOK(t, goDocument))
	equal(t, strings.Join(checked.Environments, ","), strings.Join(goDocument.Environments.Keys(), ","))
	goValues := revealAll(t, goDocument, identities)
	equal(t, goValues["FROM_GO@2"], "go ✓ <&>")
	equal(t, goValues["VERBOSE@dev"], "true")
	if !maps.Equal(checked.Values, goValues) {
		t.Fatalf("values differ:\nGo %q\nTS %q", goValues, checked.Values)
	}

	// TypeScript modifies the Go-written file, Go reads it again.
	second := plan{
		IdentityFiles: identityFiles,
		Recipients:    []planRecipient{{"dave", must[*Identity](t)(GenerateIdentity(false)).PublicKey.Token, trickyDescriptions[3]}},
		Environments:  []planEnvironment{{"0", []string{"bob", "dave"}}},
		Secrets:       []planSecret{{"FROM_TS", trickyDescriptions[1], []string{"0", "2"}, map[string]string{"0": "ts zero", "2": "ts two"}}},
	}
	modified := runTypeScript(t, node, "modify", file, second)
	text = string(must[[]byte](t)(os.ReadFile(file)))
	document = must[*Document](t)(ParseDocumentText(text, ""))
	equal(t, SerializeDocument(document), text)
	equal(t, strings.Join(document.Environments.Keys(), ","), strings.Join(modified.Environments, ","))
	equal(t, modified.OK, inspectOK(t, document))
	if got := revealAll(t, document, identities); !maps.Equal(got, modified.Values) {
		t.Fatalf("values differ:\nGo %q\nTS %q", got, modified.Values)
	}
	equal(t, slices.Contains(slices.Collect(maps.Values(modified.Values)), "ts zero"), true)
}
