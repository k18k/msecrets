package cli

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHiddenValuePrompt(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	r := alice.interactive(t, []string{"set", "API_KEY", "--all"}, []exchange{{`Value for API_KEY \(development, production\): `, "s3cr3t-value\r"}})
	ok(t, r.result)
	if r.unanswered != 0 || strings.Contains(r.screen, "s3cr3t-value") {
		t.Fatalf("unanswered %d, screen %q", r.unanswered, r.screen)
	}
	if got := alice.run(t, []string{"get", "API_KEY", "--env", "production"}).stdout; got != "s3cr3t-value" {
		t.Fatal(got)
	}
}

func TestPromptEditingAndCancel(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.interactive(t, []string{"set", "X"}, []exchange{{`Value for X`, "abcd\x7f\x7fzz\r"}}).result)
	if got := alice.run(t, []string{"get", "X"}).stdout; got != "abzz" {
		t.Fatal(got)
	}
	expectCode(t, alice.interactive(t, []string{"set", "Y"}, []exchange{{`Value for Y`, "abc\x03"}}).result, 130)
	expectCode(t, alice.run(t, []string{"get", "Y"}), 1)
}

func TestDangerousCommandsConfirm(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"set", "X", "1"}))
	declined := alice.interactive(t, []string{"rm", "X"}, []exchange{{`Delete X from every environment\? \[y/N\] `, "n\r"}})
	expectCode(t, declined.result, 2)
	expectMatch(t, declined.screen, `Aborted`)
	ok(t, alice.interactive(t, []string{"rm", "X"}, []exchange{{`\[y/N\]`, "y\r"}}).result)
	expectCode(t, alice.run(t, []string{"get", "X"}), 1)
}

func TestPassphraseProtectedIdentityFile(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	// A path wider than the terminal (110 columns): the prompt wraps instead of losing its end.
	alice.config = filepath.Join(alice.config, strings.Repeat("a-long-directory-name", 6))
	initArgs := []string{"init", "--store", "file", "--passphrase", "--name", "alice"}
	mismatch := alice.interactive(t, initArgs, []exchange{
		{`New passphrase for the identity file: `, "correct horse\r"},
		{`Repeat the passphrase: `, "wrong\r"},
	})
	expectCode(t, mismatch.result, 2)
	expectMatch(t, mismatch.screen, `do not match`)

	ok(t, alice.interactive(t, initArgs, []exchange{{`New passphrase`, "correct horse\r"}, {`Repeat the passphrase`, "correct horse\r"}}).result)
	expectMatch(t, readFile(t, filepath.Join(alice.config, "identity.txt")), `^-----BEGIN AGE ENCRYPTED FILE-----`)

	unlocked := alice.interactive(t, []string{"set", "X", "1"}, []exchange{{`Passphrase for file .*identity\.txt: `, "correct horse\r"}})
	ok(t, unlocked.result)
	if got := alice.run(t, []string{"get", "X"}, runOptions{env: map[string]string{"MSECRETS_PASSPHRASE": "correct horse"}}).stdout; got != "1" {
		t.Fatal(got)
	}
	headless := alice.run(t, []string{"get", "X"})
	expectCode(t, headless, 1)
	expectMatch(t, headless.stderr, `passphrase-protected; set MSECRETS_PASSPHRASE`)
}

func TestPassphraseProtectedSSHKey(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	key, err := filepath.Abs(filepath.Join("..", "core", "testdata", "fixtures", "ssh", "encrypted-ctr"))
	if err != nil {
		t.Fatal(err)
	}
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"recipient", "add", "ssh-user", strings.TrimSpace(readFile(t, key+".pub")), "--env", "development"}))
	ok(t, alice.run(t, []string{"set", "X", "for-ssh"}))
	r := alice.interactive(t, []string{"get", "X", "--identity", "file:" + key}, []exchange{{`Passphrase for file .*encrypted-ctr: `, "correct horse\r"}})
	ok(t, r.result)
	if r.stdout != "for-ssh" {
		t.Fatalf("%q", r.stdout)
	}
}

func TestIdentityExportAsksOnATerminal(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"identity", "new", "--store", "file"}))
	declined := alice.interactive(t, []string{"identity", "export"},
		[]exchange{{`prints your private key on the screen\. Continue\? \[y/N\] `, "n\r"}}, ptyOptions{stdoutIsTerminal: true})
	expectCode(t, declined.result, 2)
	if strings.Contains(declined.screen, "AGE-SECRET-KEY-") {
		t.Fatal("the key was printed")
	}
	redirected := alice.interactive(t, []string{"identity", "export"}, nil)
	ok(t, redirected.result)
	expectMatch(t, redirected.stdout, `(?m)^AGE-SECRET-KEY-1`)
}

// fakeKeychainTools puts stand-ins for secret-tool and security (this test binary) on a PATH of their own.
func fakeKeychainTools(t *testing.T) (path, store string) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("keychain stand-ins: Linux and macOS")
	}
	tools := t.TempDir()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"secret-tool", "security"} {
		source, err := os.Open(self)
		if err != nil {
			t.Fatal(err)
		}
		target, err := os.OpenFile(filepath.Join(tools, name), os.O_CREATE|os.O_WRONLY, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(target, source); err != nil {
			t.Fatal(err)
		}
		source.Close()
		target.Close()
	}
	return tools + string(os.PathListSeparator) + os.Getenv("PATH"), filepath.Join(tools, "store.json")
}

func TestKeychainStorage(t *testing.T) {
	path, store := fakeKeychainTools(t)
	env := runOptions{env: map[string]string{"PATH": path, "MSECRETS_TEST_KEYCHAIN": store}}
	ws := newWorkspace(t)
	alice := ws.person("alice")
	init := alice.run(t, []string{"init", "--name", "alice"}, env)
	ok(t, init)
	expectMatch(t, init.stderr, `Created your identity \(OS keychain\)`)
	if got := readFile(t, filepath.Join(alice.config, "config.json")); got != "{\n  \"identities\": [\n    \"keychain:default\"\n  ]\n}\n" {
		t.Fatalf("%q", got)
	}
	expectMatch(t, readFile(t, store), `AGE-SECRET-KEY-1`)
	ok(t, alice.run(t, []string{"set", "X", "from-keychain"}, env))
	if got := alice.run(t, []string{"get", "X"}, env).stdout; got != "from-keychain" {
		t.Fatal(got)
	}
	expectMatch(t, alice.run(t, []string{"whoami"}, env).stdout, `from OS keychain \(default\)`)
}

func TestKeychainIdentityIsNeverReplaced(t *testing.T) {
	path, store := fakeKeychainTools(t)
	env := runOptions{env: map[string]string{"PATH": path, "MSECRETS_TEST_KEYCHAIN": store}}
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"identity", "new", "--store", "keychain"}, env))
	original := readFile(t, store)

	again := alice.run(t, []string{"identity", "new", "--store", "keychain"}, env)
	expectCode(t, again, 1)
	expectMatch(t, again.stderr, `already holds an msecrets identity "default"`)
	if readFile(t, store) != original {
		t.Fatal("replaced")
	}
	// A new config directory (no sources configured) must not overwrite it either.
	init := ws.person("alice-on-a-new-config").run(t, []string{"init", "--name", "alice"}, env)
	expectCode(t, init, 1)
	expectMatch(t, init.stderr, "msecrets identity use keychain:default")
	if readFile(t, store) != original {
		t.Fatal("replaced")
	}

	ok(t, alice.run(t, []string{"identity", "new", "--store", "keychain", "--account", "work"}, env))
	entries := map[string]string{}
	if err := json.Unmarshal([]byte(readFile(t, store)), &entries); err != nil || len(entries) != 2 {
		t.Fatal(entries, err)
	}
}

func TestKeychainUnavailableFallsBackToAFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX only")
	}
	// An empty PATH: no keychain tool can run, and the real keychain is never touched.
	ws := newWorkspace(t)
	alice := ws.person("alice")
	init := alice.run(t, []string{"init", "--name", "alice"}, runOptions{env: map[string]string{"PATH": t.TempDir()}})
	ok(t, init)
	expectMatch(t, init.stderr, `OS keychain unavailable`)
	identityFile := filepath.Join(alice.config, "identity.txt")
	expectMatch(t, readFile(t, identityFile), `AGE-SECRET-KEY-1`)
	info, err := os.Stat(identityFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode(), err)
	}
}
