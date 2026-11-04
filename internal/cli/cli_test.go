package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/k18k/msecrets/internal/core"
)

func parseFile(t *testing.T, ws *workspace) *core.Document {
	t.Helper()
	document, err := core.ParseDocumentText(readFile(t, filepath.Join(ws.project, "msecrets.json")), "")
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func TestInitSetGetLsCheck(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")

	init := alice.run(t, []string{"init", "--store", "file", "--name", "alice"})
	ok(t, init)
	expectMatch(t, init.stderr, `Created msecrets\.json \(development, production\); you are recipient "alice"`)
	expectMatch(t, readFile(t, filepath.Join(alice.config, "config.json")), `"file:.*identity\.txt"`)
	expectCode(t, alice.run(t, []string{"init", "--store", "file"}), 1)

	ok(t, alice.run(t, []string{"set", "DATABASE_URL", "postgres://dev"}))
	ok(t, alice.run(t, []string{"set", "DATABASE_URL", "--env", "production"}, runOptions{input: "postgres://prod\n"}))
	ok(t, alice.run(t, []string{"set", "API_KEY", "key-1", "--all", "-d", "Payments"}))

	for _, check := range []struct {
		args []string
		env  map[string]string
		want string
	}{
		{[]string{"get", "DATABASE_URL"}, nil, "postgres://dev"},
		{[]string{"get", "DATABASE_URL", "-e", "production"}, nil, "postgres://prod"},
		{[]string{"get", "DATABASE_URL"}, map[string]string{"MSECRETS_ENV": "production"}, "postgres://prod"},
	} {
		if got := alice.run(t, check.args, runOptions{env: check.env}).stdout; got != check.want {
			t.Fatalf("%v: %q, want %q", check.args, got, check.want)
		}
	}

	ls := alice.run(t, []string{"ls"})
	ok(t, ls)
	expectMatch(t, ls.stdout, `API_KEY\s+●\s+●\s+Payments`)
	ok(t, alice.run(t, []string{"check"}))

	ok(t, alice.run(t, []string{"env", "add", "staging"}))
	listing := alice.run(t, []string{"ls"})
	ok(t, listing) // ls only reports problems; check fails on them
	expectMatch(t, listing.stdout, `error DATABASE_URL has no value in "staging"`)
	failing := alice.run(t, []string{"check"})
	expectCode(t, failing, 1)
	expectMatch(t, failing.stdout, `DATABASE_URL has no value in "staging"`)

	var report struct {
		OK      bool `json:"ok"`
		Secrets map[string]struct {
			Values map[string]string `json:"values"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal([]byte(alice.run(t, []string{"ls", "--json"}).stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.OK || report.Secrets["API_KEY"].Values["staging"] != "missing" {
		t.Fatalf("%+v", report)
	}
}

func TestTeamWorkflow(t *testing.T) {
	ws := newWorkspace(t)
	alice, bob := ws.person("alice"), ws.person("bob")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"set", "DATABASE_URL", "dev-url"}))
	ok(t, alice.run(t, []string{"set", "DATABASE_URL", "prod-url", "--env", "production"}))

	// bob joins with access to development; he cannot re-encrypt anything yet.
	joined := bob.run(t, []string{"join", "--store", "file", "--name", "bob", "--env", "development"})
	ok(t, joined)
	expectMatch(t, joined.stderr, "a member runs `msecrets sync`")
	stale := bob.run(t, []string{"get", "DATABASE_URL"})
	expectCode(t, stale, 1)
	expectMatch(t, stale.stderr, "out of date for you; ask a member to run `msecrets sync`")
	expectCode(t, alice.run(t, []string{"check"}), 1)

	synced := alice.run(t, []string{"sync"})
	ok(t, synced)
	expectMatch(t, synced.stderr, `Re-encrypted 1 value`)
	if got := bob.run(t, []string{"get", "DATABASE_URL"}).stdout; got != "dev-url" {
		t.Fatal(got)
	}
	expectCode(t, bob.run(t, []string{"get", "DATABASE_URL", "--env", "production"}), 1)

	// A machine identity for production, handed to the runtime through MSECRETS_IDENTITY.
	machine := alice.run(t, []string{"recipient", "add", "deploy", "--generate", "--env", "production", "-d", "CI deploys"})
	ok(t, machine)
	identity := identityFrom(machine.stdout)
	expectMatch(t, identity, `^AGE-SECRET-KEY-1`)
	exported := ws.person("runtime").run(t, []string{"export", "--format", "json", "--env", "production"}, runOptions{env: map[string]string{"MSECRETS_IDENTITY": identity}})
	ok(t, exported)
	if exported.stdout != "{\n  \"DATABASE_URL\": \"prod-url\"\n}\n" {
		t.Fatalf("%q", exported.stdout)
	}

	expectMatch(t, bob.run(t, []string{"whoami"}).stdout, `recipient bob: development \(read/write\)`)
	recipients := alice.run(t, []string{"recipient", "ls"}).stdout
	expectMatch(t, recipients, `alice \(you\)`)
	expectMatch(t, recipients, `deploy\s+x25519 read-only\s+production\s+CI deploys`)

	// bob cannot revoke the machine: he cannot re-encrypt production.
	refused := bob.run(t, []string{"revoke", "deploy", "production"})
	expectCode(t, refused, 1)
	expectMatch(t, refused.stderr, `requires re-encrypting values you cannot decrypt`)
	expectMatch(t, refused.stderr, `\[ACCESS_DENIED\]`)

	revoked := alice.run(t, []string{"revoke", "bob", "development"})
	ok(t, revoked)
	expectMatch(t, revoked.stderr, `could read these values and may have kept copies`)
	expectCode(t, bob.run(t, []string{"get", "DATABASE_URL"}), 1)
	ok(t, alice.run(t, []string{"check"}))

	ok(t, alice.run(t, []string{"recipient", "rm", "bob", "--yes"}))
	if parseFile(t, ws).Recipients.Has("bob") {
		t.Fatal("bob is still a recipient")
	}
}

func TestStructuralChanges(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice", "--env", "development,production"}))
	ok(t, alice.run(t, []string{"set", "A", "1", "--all"}))
	ok(t, alice.run(t, []string{"set", "SENTRY", "dsn", "--env", "production"}))

	ok(t, alice.run(t, []string{"mv", "A", "B"}))
	if got := alice.run(t, []string{"get", "B"}).stdout; got != "1" {
		t.Fatal(got)
	}
	ok(t, alice.run(t, []string{"describe", "B", "The", "B", "value"}))
	ok(t, alice.run(t, []string{"scope", "SENTRY", "production"}))
	ok(t, alice.run(t, []string{"check"}))

	expectCode(t, alice.run(t, []string{"scope", "B", "production"}), 2) // needs --yes without a terminal
	ok(t, alice.run(t, []string{"scope", "B", "production", "--yes"}))
	ok(t, alice.run(t, []string{"unset", "B", "--env", "production"}))
	expectCode(t, alice.run(t, []string{"check"}), 1)
	expectCode(t, alice.run(t, []string{"rm", "B"}), 2)
	ok(t, alice.run(t, []string{"rm", "B", "--yes"}))

	ok(t, alice.run(t, []string{"env", "mv", "production", "prod"}))
	if got := alice.run(t, []string{"get", "SENTRY", "--env", "prod"}).stdout; got != "dsn" {
		t.Fatal(got)
	}
	expectMatch(t, alice.run(t, []string{"env", "ls"}).stdout, `prod\s+1/1\s+alice`)
	ok(t, alice.run(t, []string{"env", "rm", "prod", "--yes"}))
	ok(t, alice.run(t, []string{"recipient", "mv", "alice", "alice.smith"}))
	ok(t, alice.run(t, []string{"check"}))

	document := parseFile(t, ws)
	if !reflect.DeepEqual(document.Environments.Keys(), []string{"development"}) || document.Secrets.Len() != 0 ||
		!reflect.DeepEqual(document.Recipients.Keys(), []string{"alice.smith"}) {
		t.Fatal(core.SerializeDocument(document))
	}
}

func TestRotateCopyRecipientsDescribe(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"set", "TOKEN", "t", "--all"}))
	first := identityFrom(alice.run(t, []string{"recipient", "add", "ci", "--generate", "--env", "production"}).stdout)
	rotated := alice.run(t, []string{"recipient", "rotate", "ci", "--generate"})
	ok(t, rotated)
	expectMatch(t, rotated.stderr, `Rotated the key of "ci" \(1 value\(s\) re-encrypted\)`)
	second := identityFrom(rotated.stdout)
	if first == second || second == "" {
		t.Fatal("the key did not change")
	}
	runtime := ws.person("runtime")
	get := []string{"get", "TOKEN", "--env", "production"}
	expectCode(t, runtime.run(t, get, runOptions{env: map[string]string{"MSECRETS_IDENTITY": first}}), 1)
	if got := runtime.run(t, get, runOptions{env: map[string]string{"MSECRETS_IDENTITY": second}}).stdout; got != "t" {
		t.Fatal(got)
	}
	// Machine keys are read-only.
	expectCode(t, runtime.run(t, []string{"set", "TOKEN", "x", "--env", "production"}, runOptions{env: map[string]string{"MSECRETS_IDENTITY": second}}), 1)

	ok(t, alice.run(t, []string{"env", "add", "staging", "--from", "production"}))
	expectMatch(t, alice.run(t, []string{"env", "ls"}).stdout, `staging\s+0/1\s+alice, ci`)
	ok(t, alice.run(t, []string{"describe", "TOKEN", "API", "token"}))
	ok(t, alice.run(t, []string{"describe", "TOKEN"}))
	synced := alice.run(t, []string{"sync"})
	ok(t, synced)
	expectMatch(t, synced.stderr, `Everything is up to date`)
}

func TestWhoamiAndAddingPeopleByKey(t *testing.T) {
	ws := newWorkspace(t)
	alice, bob := ws.person("alice"), ws.person("bob")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, bob.run(t, []string{"identity", "new", "--store", "file"}))
	expectMatch(t, bob.run(t, []string{"whoami"}).stdout, `not a recipient of this file`)

	bobKey := strings.TrimSpace(bob.run(t, []string{"identity", "show"}).stdout)
	ok(t, alice.run(t, []string{"recipient", "add", "bob", bobKey, "--env", "development", "-d", "Backend"}))
	expectMatch(t, bob.run(t, []string{"whoami"}).stdout, `recipient bob: development \(read/write\)`)
	expectCode(t, alice.run(t, []string{"recipient", "add", "bob2", bobKey}), 1)
	expectCode(t, alice.run(t, []string{"recipient", "add", "x"}), 2)
}

// childScript runs the test binary as `run`'s child: it records variables and exits with a code.
func childScript(t *testing.T, ws *workspace, variables string, exit string) (args []string, env map[string]string, output string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output = filepath.Join(ws.root, "child.json")
	return []string{self}, map[string]string{
		"MSECRETS_TEST_HELPER": "env", "MSECRETS_TEST_VARS": variables,
		"MSECRETS_TEST_OUTPUT": output, "MSECRETS_TEST_EXIT": exit,
	}, output
}

func childValues(t *testing.T, output string) map[string]*string {
	t.Helper()
	values := map[string]*string{}
	if err := json.Unmarshal([]byte(readFile(t, output)), &values); err != nil {
		t.Fatal(err)
	}
	return values
}

func value(v *string) string {
	if v == nil {
		return "<unset>"
	}
	return *v
}

func TestRunInjectsSecretsHidesIdentityPassesExitCode(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice", "--env", "development"}))
	ok(t, alice.run(t, []string{"set", "GREETING", "hello world"}))
	ok(t, alice.run(t, []string{"set", "PRESET", "from-file"}))

	child, env, output := childScript(t, ws, "GREETING,PRESET,MSECRETS_IDENTITY", "7")
	env["PRESET"] = "explicit"
	env["MSECRETS_IDENTITY"] = readFile(t, filepath.Join(alice.config, "identity.txt"))
	expectCode(t, alice.run(t, append([]string{"run", "--"}, child...), runOptions{env: env}), 7)
	values := childValues(t, output)
	if value(values["GREETING"]) != "hello world" || value(values["PRESET"]) != "explicit" || values["MSECRETS_IDENTITY"] != nil {
		t.Fatalf("%v %v %v", value(values["GREETING"]), value(values["PRESET"]), value(values["MSECRETS_IDENTITY"]))
	}

	delete(env, "MSECRETS_IDENTITY")
	expectCode(t, alice.run(t, append([]string{"run", "--override"}, child...), runOptions{env: env}), 7)
	if got := value(childValues(t, output)["PRESET"]); got != "from-file" {
		t.Fatal(got)
	}

	expectCode(t, alice.run(t, []string{"run"}), 2)
	expectCode(t, alice.run(t, []string{"run", "--", "msecrets-no-such-command"}), 2)
}

func TestRunHidesIdentitiesFromAnyVariable(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice", "--env", "development"}))
	ok(t, alice.run(t, []string{"set", "GREETING", "hello"}))
	child, env, output := childScript(t, ws, "GREETING,APP_PRIVATE_KEY,MSECRETS_PASSPHRASE", "0")
	env["APP_PRIVATE_KEY"] = readFile(t, filepath.Join(alice.config, "identity.txt"))
	env["MSECRETS_PASSPHRASE"] = "unused"
	check := func() {
		values := childValues(t, output)
		if value(values["GREETING"]) != "hello" || values["APP_PRIVATE_KEY"] != nil || values["MSECRETS_PASSPHRASE"] != nil {
			t.Fatalf("%v", values)
		}
	}

	ok(t, alice.run(t, append([]string{"run", "--identity", "env:APP_PRIVATE_KEY", "--"}, child...), runOptions{env: env}))
	check()
	writeFile(t, filepath.Join(alice.config, "config.json"), `{"identities": ["env:APP_PRIVATE_KEY"]}`)
	ok(t, alice.run(t, append([]string{"run", "--"}, child...), runOptions{env: env}))
	check()
}

func TestRunRefusesAnIncompleteEnvironment(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"set", "ONLY_DEV", "x"}))
	child, env, _ := childScript(t, ws, "X", "0")
	r := alice.run(t, append([]string{"run", "--env", "production", "--"}, child...), runOptions{env: env})
	expectCode(t, r, 1)
	expectMatch(t, r.stderr, `incomplete; these secrets have no value: ONLY_DEV`)
}

func TestImportExportRoundTrip(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice", "--env", "development"}))
	writeFile(t, filepath.Join(ws.project, ".env"), strings.Join([]string{
		"# comment", "PLAIN=value", `export QUOTED="two words"`, `MULTI="line1\nline2"`, "SINGLE='$NOT_EXPANDED'", "EMPTY=", "",
	}, "\n"))

	imported := alice.run(t, []string{"import", ".env"})
	ok(t, imported)
	expectMatch(t, imported.stderr, `Imported 5 secret`)
	expectMatch(t, alice.run(t, []string{"import", "-"}, runOptions{input: "PLAIN=changed\n"}).stderr, `Kept existing values`)

	exported := alice.run(t, []string{"export"})
	ok(t, exported)
	entries, err := parseDotenv(exported.stdout)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range entries {
		got[e.Name] = e.Value
	}
	want := map[string]string{"EMPTY": "", "MULTI": "line1\nline2", "PLAIN": "value", "QUOTED": "two words", "SINGLE": "$NOT_EXPANDED"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	expectMatch(t, alice.run(t, []string{"export", "--format", "shell"}).stdout, `(?m)^export MULTI='line1\nline2'$`)
	expectMatch(t, alice.run(t, []string{"export", "--format", "powershell"}).stdout, `(?m)^\$env:SINGLE = '\$NOT_EXPANDED'$`)
	expectCode(t, alice.run(t, []string{"export", "--format", "xml"}), 2)
}

func TestIdentityNewShowUseExport(t *testing.T) {
	ws := newWorkspace(t)
	carol := ws.person("carol")
	printed := carol.run(t, []string{"identity", "new", "--store", "print"})
	ok(t, printed)
	secret := identityFrom(printed.stdout)
	expectMatch(t, printed.stderr, `Public key: msecrets1`)

	keyFile := filepath.Join(ws.root, "carol.key")
	writeFile(t, keyFile, secret+"\n")
	used := carol.run(t, []string{"identity", "use", "file:" + keyFile})
	ok(t, used)
	shown := carol.run(t, []string{"identity", "show"})
	if strings.TrimSpace(shown.stdout) != strings.TrimSpace(used.stdout) {
		t.Fatal(shown.stdout, used.stdout)
	}
	if identityFrom(carol.run(t, []string{"identity", "export"}).stdout) != secret {
		t.Fatal("export differs")
	}
	expectCode(t, carol.run(t, []string{"identity", "use", "env:NOT_SET"}), 1)
	viaFlag := ws.person("dave").run(t, []string{"identity", "show", "--identity", secret})
	if strings.TrimSpace(viaFlag.stdout) != strings.TrimSpace(shown.stdout) {
		t.Fatal(viaFlag)
	}
}

func TestIdentityUseStoresAbsolutePaths(t *testing.T) {
	ws := newWorkspace(t)
	erin := ws.person("erin")
	printed := erin.run(t, []string{"identity", "new", "--store", "print"})
	writeFile(t, filepath.Join(ws.project, "erin.key"), identityFrom(printed.stdout)+"\n")
	ok(t, erin.run(t, []string{"identity", "use", "file:erin.key"}))
	var config struct{ Identities []string }
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(erin.config, "config.json"))), &config); err != nil || len(config.Identities) != 1 {
		t.Fatal(config, err)
	}
	stored, isFile := strings.CutPrefix(config.Identities[0], "file:")
	// The same file, however the OS spells the directory (/private/var on macOS, RUNNER~1 on Windows).
	if storedInfo, err := os.Stat(stored); !isFile || !filepath.IsAbs(stored) || err != nil || !os.SameFile(storedInfo, must[os.FileInfo](t)(os.Stat(filepath.Join(ws.project, "erin.key")))) {
		t.Fatalf("%q", config.Identities[0])
	}
	nested := filepath.Join(ws.project, "src")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	shown := erin.run(t, []string{"identity", "show"}, runOptions{cwd: nested})
	ok(t, shown)
	expectMatch(t, shown.stdout, `^msecrets1`)
}

func TestNoIdentityHelpfulErrors(t *testing.T) {
	nobody := newWorkspace(t).person("nobody")
	expectMatch(t, nobody.run(t, []string{"identity", "show"}).stderr, `No msecrets identity found`)
	expectCode(t, nobody.run(t, []string{"whoami"}), 1)
}

func TestUsage(t *testing.T) {
	user := newWorkspace(t).person("x")
	help := user.run(t, []string{"--help"})
	ok(t, help)
	expectMatch(t, help.stdout, `Get started:[\s\S]*init[\s\S]*CI and git:`)
	expectMatch(t, user.run(t, []string{"set", "--help"}).stdout, `Usage: msecrets set <NAME> \[VALUE\]`)
	expectMatch(t, user.run(t, []string{"set", "--help"}).stdout, `Examples:`)
	expectMatch(t, user.run(t, []string{"help", "env", "add"}).stdout, `Usage: msecrets env add <NAME>`)
	expectMatch(t, user.run(t, []string{"env", "--help"}).stdout, `env rm <NAME>`)
	if got := user.run(t, []string{"--version"}).stdout; got != "msecrets 4.1.0\n" {
		t.Fatalf("%q", got)
	}
	ok(t, user.run(t, nil)) // no terminal: prints help

	unknown := user.run(t, []string{"lst"})
	expectCode(t, unknown, 2)
	expectMatch(t, unknown.stderr, `did you mean "ls"`)
	expectMatch(t, user.run(t, []string{"env", "nope"}).stderr, `try: env ls, env add, env rm, env mv`)
	expectCode(t, user.run(t, []string{"help", "nope"}), 2)
	expectMatch(t, user.run(t, []string{"ls", "--nope"}).stderr, `Unknown option '--nope'`)
	expectCode(t, user.run(t, []string{"get"}), 2)
	missing := user.run(t, []string{"ls"})
	expectCode(t, missing, 1)
	expectMatch(t, missing.stderr, `No msecrets\.json found`)
	expectCode(t, user.run(t, []string{"tui"}), 2)
}

func TestGlobalOptionsBeforeTheCommand(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"-f", "other.ms.json", "init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"-f", "other.ms.json", "set", "X", "1"}))
	if got := alice.run(t, []string{"--file", "other.ms.json", "get", "X"}).stdout; got != "1" {
		t.Fatal(got)
	}
	// Options before `run` and its command.
	child, env, output := childScript(t, ws, "X", "3")
	expectCode(t, alice.run(t, append([]string{"-f", "other.ms.json", "-e", "development", "run"}, child...), runOptions{env: env}), 3)
	if got := value(childValues(t, output)["X"]); got != "1" {
		t.Fatal(got)
	}
}

func TestCompletion(t *testing.T) {
	ws := newWorkspace(t)
	alice := ws.person("alice")
	ok(t, alice.run(t, []string{"init", "--store", "file", "--name", "alice"}))
	ok(t, alice.run(t, []string{"set", "DATABASE_URL", "x"}))
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		script := alice.run(t, []string{"completion", shell})
		ok(t, script)
		expectMatch(t, script.stdout, `msecrets`)
	}
	expectMatch(t, alice.run(t, []string{"__complete", "get", ""}).stdout, `(?m)^DATABASE_URL$`)
	expectMatch(t, alice.run(t, []string{"__complete", "set", "X", "--env", ""}).stdout, `(?m)^production$`)
	expectMatch(t, alice.run(t, []string{"__complete", "grant", "alice", ""}).stdout, `(?m)^development$`)
}
