package cli

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestPlainValues(t *testing.T) {
	ws := newWorkspace(t)
	alice, stranger := ws.person("alice"), ws.person("stranger")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"set", "DATABASE_URL", "postgres://dev"}))
	set := alice.run(t, []string{"set", "API_URL", "https://api.example.com", "--plain", "--all"})
	ok(t, set)
	expectMatch(t, set.stderr, `Set API_URL as plain text in development, production`)
	expectMatch(t, readFile(t, filepath.Join(ws.project, "msecrets.json")), `"value": "https://api.example.com"`)

	// Updates stay plain; encrypted secrets never turn into plain text.
	ok(t, alice.run(t, []string{"set", "API_URL", "http://localhost", "--env", "development"}))
	refused := alice.run(t, []string{"set", "DATABASE_URL", "x", "--plain"})
	expectCode(t, refused, 2)
	expectMatch(t, refused.stderr, `DATABASE_URL is an encrypted secret`)
	expectMatch(t, alice.run(t, []string{"ls"}).stdout, `API_URL \(plain\)\s+●\s+●`)

	// Plain values need no key: not to read them, and not to run with an environment that has only plain values.
	if got := stranger.run(t, []string{"get", "API_URL", "--env", "production"}).stdout; got != "https://api.example.com" {
		t.Fatal(got)
	}
	expectCode(t, stranger.run(t, []string{"get", "DATABASE_URL"}), 1)
	ok(t, alice.run(t, []string{"scope", "DATABASE_URL", "development"}))
	ok(t, alice.run(t, []string{"check"}))
	exported := stranger.run(t, []string{"export", "--env", "production"})
	ok(t, exported)
	if exported.stdout != "API_URL=https://api.example.com\n" {
		t.Fatalf("%q", exported.stdout)
	}
}

// lastLine is the last non-empty line of output (a generated password).
func lastLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	return lines[len(lines)-1]
}

func TestPasswordMembers(t *testing.T) {
	ws := newWorkspace(t)
	alice, dana := ws.person("alice"), ws.person("dana")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"set", "DATABASE_URL", "postgres://dev"}))

	// Without a terminal, the password is generated and printed once.
	added := alice.run(t, []string{"recipient", "add", "dana", "--password", "--env", "development"})
	ok(t, added)
	password := lastLine(added.stdout)
	expectMatch(t, password, `^[2-9a-z]{5}(-[2-9a-z]{5}){3}$`)
	expectMatch(t, added.stderr, `shown only once`)
	expectMatch(t, readFile(t, filepath.Join(ws.project, "msecrets.json")), `"salt": "[A-Za-z0-9+/]{22}=="`)
	expectMatch(t, alice.run(t, []string{"recipient", "ls"}).stdout, `dana\s+x25519 password\s+development`)

	// dana has no key on her machine, only the password.
	withPassword := func(password string) runOptions {
		return runOptions{env: map[string]string{"MSECRETS_PASSPHRASE": password}}
	}
	expectCode(t, dana.run(t, []string{"get", "DATABASE_URL"}), 1)
	got := dana.run(t, []string{"get", "DATABASE_URL"}, withPassword(password))
	ok(t, got)
	if got.stdout != "postgres://dev" {
		t.Fatal(got.stdout)
	}
	wrong := dana.run(t, []string{"get", "DATABASE_URL"}, withPassword(password+"x"))
	expectCode(t, wrong, 1)
	expectMatch(t, wrong.stderr, `Wrong password for dana`)
	expectMatch(t, dana.run(t, []string{"set", "FROM_DANA", "hi"}, withPassword(password)).stderr, `signed by dana`)

	// A new password: the old one unlocks the values, the new one replaces it.
	rotated := dana.run(t, []string{"recipient", "rotate", "dana", "--password"}, withPassword(password))
	ok(t, rotated)
	next := lastLine(rotated.stdout)
	expectCode(t, dana.run(t, []string{"get", "FROM_DANA"}, withPassword(password)), 1)
	if got := dana.run(t, []string{"get", "FROM_DANA"}, withPassword(next)).stdout; got != "hi" {
		t.Fatal(got)
	}
	expectMatch(t, alice.run(t, []string{"ls"}).stdout, `FROM_DANA\s+●`)

	// alice has her own key, so she is never asked for a password.
	expectMatch(t, alice.run(t, []string{"get", "FROM_DANA"}).stdout, `^hi$`)
}

func TestInitAsksHowToUnlock(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	const password = "correct horse battery staple"
	initialized := alice.interactive(t, []string{"init", "--name", "alice"}, []exchange{
		{`How do you want to unlock secrets\?.*3\) a password you type.*Choose \[1\]: `, "3\r"},
		{`New password for "alice"`, password + "\r"},
		{`Repeat the password: `, password + "\r"},
	})
	ok(t, initialized.result)
	expectMatch(t, initialized.screen, `You are a password member`)
	if strings.Contains(initialized.screen, password) {
		t.Fatal("the password was echoed")
	}
	expectMatch(t, readFile(t, filepath.Join(ws.project, "msecrets.json")), `"salt"`)

	ok(t, alice.interactive(t, []string{"set", "X"}, []exchange{
		{`Password for msecrets\.json \(alice; Enter skips\): `, password + "\r"},
		{`Value for X`, "secret\r"},
	}).result)
	read := alice.interactive(t, []string{"get", "X"}, []exchange{{`Password for msecrets\.json`, password + "\r"}})
	ok(t, read.result)
	if read.stdout != "secret" {
		t.Fatalf("%q", read.stdout)
	}

	// An existing key is used, and init says which one.
	other := newWorkspace(t)
	bob := other.person("bob")
	ok(t, bob.run(t, []string{"identity", "new", "--store", "file"}))
	joined := bob.run(t, []string{"init", "--name", "bob"})
	ok(t, joined)
	expectMatch(t, joined.stderr, `Using your existing key from file \S+identity\.txt \(msecrets1\S+\)`)
	if regexp.MustCompile(`Choose`).MatchString(joined.stderr) {
		t.Fatal("asked although a key exists")
	}
}
