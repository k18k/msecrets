package core

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// The test binary doubles as a helper process (see helperCommand).
func TestMain(m *testing.M) {
	switch os.Getenv("MSECRETS_TEST_HELPER") {
	case "print":
		fmt.Print(os.Getenv("MSECRETS_TEST_OUTPUT"))
		os.Exit(0)
	case "exit":
		os.Exit(3)
	case "update":
		// A concurrent writer: holds the document long enough that writers overlap.
		_, err := UpdateDocumentFile(NativeHost(), os.Getenv("MSECRETS_TEST_FILE"), func(document *Document) (struct{}, error) {
			time.Sleep(50 * time.Millisecond)
			document.Secrets.Set(os.Getenv("MSECRETS_TEST_OUTPUT"), &SecretEntry{})
			return struct{}{}, nil
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	case "cat":
		data, err := os.ReadFile(os.Getenv("MSECRETS_TEST_OUTPUT"))
		if err != nil {
			os.Exit(2)
		}
		os.Stdout.Write(data)
		os.Exit(0)
	}
	os.Setenv("MSECRETS_CONFIG_DIR", os.DevNull)
	os.Exit(m.Run())
}

// helperHost runs the test binary as a helper process: mode "print" prints output,
// "exit" exits with 3, "cat" prints the file named by output (relative to the working directory).
func helperHost(mode, output string) Host {
	return WithEnv(NativeHost(), map[string]string{
		"MSECRETS_TEST_HELPER": mode,
		"MSECRETS_TEST_OUTPUT": output,
		"PATH":                 os.Getenv("PATH"),
		"SYSTEMROOT":           os.Getenv("SYSTEMROOT"),
	})
}

// testHost overrides the platform of a host.
type testHost struct {
	Host
	platform string
}

func (h testHost) Platform() string { return h.platform }

func check(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func must[T any](t testing.TB) func(T, error) T {
	return func(value T, err error) T {
		t.Helper()
		check(t, err)
		return value
	}
}

// expectError fails unless err is an *Error with the code ("" for any) and a message matching pattern ("" for any).
func expectError(t *testing.T, err error, code ErrorCode, pattern string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error (%s %s)", code, pattern)
	}
	if code != "" && !IsError(err, code) || code == "" && !IsError(err) {
		t.Fatalf("expected %s, got %#v", code, err)
	}
	if pattern != "" && !regexp.MustCompile(pattern).MatchString(err.Error()) {
		t.Fatalf("expected an error matching %q, got %q", pattern, err.Error())
	}
}

func equal[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func writeFile(t testing.TB, path, text string) {
	t.Helper()
	check(t, os.MkdirAll(filepath.Dir(path), 0o755))
	check(t, os.WriteFile(path, []byte(text), 0o644))
}

type team struct{ alice, bob, carol, ci *Identity }

func newTeam(t testing.TB) team {
	generate := func() *Identity { return must[*Identity](t)(GenerateIdentity(false)) }
	return team{generate(), generate(), generate(), generate()}
}

// readOnlyToken is the plain, encrypt-only age1… form of an identity's public key.
func readOnlyToken(t testing.TB, identity *Identity) string {
	return must[*PublicKey](t)(ReadOnlyPublicKey(identity.PublicKey)).Token
}

// sampleDocument:
//   - development: alice, bob
//   - production: alice, ci (read-only age1 key)
//   - DATABASE_URL in both environments, DEBUG only in development
func sampleDocument(t testing.TB) (*Document, team) {
	t.Helper()
	people := newTeam(t)
	document := CreateDocument()
	must[*RecipientEntry](t)(AddRecipient(document, "alice", people.alice.PublicKey.Token, ""))
	must[*RecipientEntry](t)(AddRecipient(document, "bob", people.bob.PublicKey.Token, ""))
	must[*RecipientEntry](t)(AddRecipient(document, "ci", readOnlyToken(t, people.ci), ""))
	check(t, AddEnvironment(document, "development", []string{"alice", "bob"}))
	check(t, AddEnvironment(document, "production", []string{"alice", "ci"}))
	set := func(signer *Identity, secret, environment, value string) {
		must[*SealedValue](t)(SetValue(document, []*Identity{signer}, SetValueInput{Secret: secret, Environment: environment, Value: value}))
	}
	set(people.alice, "DATABASE_URL", "development", "postgres://dev")
	set(people.alice, "DATABASE_URL", "production", "postgres://prod")
	set(people.bob, "DEBUG", "development", "true")
	must[[]string](t)(ScopeSecret(document, "DEBUG", []string{"development"}))
	return document, people
}

// copyDocument round-trips a document through its file form.
func copyDocument(t *testing.T, document *Document) *Document {
	t.Helper()
	return must[*Document](t)(ParseDocumentText(SerializeDocument(document), ""))
}

func parseJSONValue(t *testing.T, text string) *Map[any] {
	t.Helper()
	return must[any](t)(ParseJSON(text)).(*Map[any])
}

// object walks nested objects of a JSON value.
func object(value any, path ...string) *Map[any] {
	current := value.(*Map[any])
	for _, key := range path {
		next, _ := current.Get(key)
		current = next.(*Map[any])
	}
	return current
}
