package core

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"filippo.io/age"
)

func tokens(t *testing.T, source IdentitySource) string {
	t.Helper()
	loaded := must[[]LoadedIdentity](t)(source.Load())
	names := make([]string, len(loaded))
	for index, entry := range loaded {
		names[index] = entry.Identity.PublicKey.Token
	}
	return strings.Join(names, ",")
}

func TestFromEnv(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	env := map[string]string{"MSECRETS_IDENTITY": identity.Secret}
	h := WithEnv(NativeHost(), env)
	equal(t, tokens(t, FromEnv("MSECRETS_IDENTITY", SourceOptions{Host: h})), identity.PublicKey.Token)
	_, present := env["MSECRETS_IDENTITY"]
	equal(t, present, false)
	equal(t, tokens(t, FromEnv("MSECRETS_IDENTITY", SourceOptions{Host: h})), "")

	kept := map[string]string{"KEY": identity.Secret}
	tokens(t, FromEnv("KEY", SourceOptions{Host: WithEnv(NativeHost(), kept), NoScrub: true}))
	equal(t, kept["KEY"], identity.Secret)

	_, err := FromEnv("X", SourceOptions{Host: WithEnv(NativeHost(), map[string]string{"X": "garbage"})}).Load()
	expectError(t, err, CodeIdentitySource, "^env X: ")
}

func TestFromFile(t *testing.T) {
	directory := t.TempDir()
	identity := must[*Identity](t)(GenerateIdentity(false))
	writeFile(t, filepath.Join(directory, "key.txt"), FormatIdentityFile(identity, ""))
	options := SourceOptions{Cwd: directory}
	equal(t, tokens(t, must[IdentitySource](t)(FromFile("key.txt", false, options))), identity.PublicKey.Token)
	equal(t, tokens(t, must[IdentitySource](t)(FromFile("missing.txt", true, options))), "")
	_, err := must[IdentitySource](t)(FromFile("missing.txt", false, options)).Load()
	expectError(t, err, CodeIdentitySource, "")
}

func TestFromCommand(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	print := must[IdentitySource](t)(FromCommand([]string{os.Args[0]}, CommandOptions{SourceOptions: SourceOptions{Host: helperHost("print", identity.Secret+"\n")}}))
	equal(t, tokens(t, print), identity.PublicKey.Token)

	_, err := must[IdentitySource](t)(FromCommand([]string{os.Args[0]}, CommandOptions{SourceOptions: SourceOptions{Host: helperHost("exit", "")}})).Load()
	expectError(t, err, CodeIdentitySource, "failed")
	_, err = must[IdentitySource](t)(FromCommand([]string{"msecrets-definitely-not-installed"}, CommandOptions{})).Load()
	expectError(t, err, CodeIdentitySource, "is not installed or not on PATH")
	_, err = FromCommand(nil, CommandOptions{})
	expectError(t, err, CodeUsage, "")
}

func TestPassphraseProtectedIdentityFile(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	path := filepath.Join(t.TempDir(), "identity.age")
	recipient := must[age.Recipient](t)(ScryptRecipient("pw", 10))
	writeFile(t, path, string(must[[]byte](t)(EncryptAge([]byte(FormatIdentityFile(identity, "")), []age.Recipient{recipient}))))
	options := SourceOptions{Passphrase: func(string) (string, error) { return "pw", nil }}
	equal(t, tokens(t, must[IdentitySource](t)(FromFile(path, false, options))), identity.PublicKey.Token)
}

func TestCommandWorkingDirectory(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	directory := t.TempDir()
	writeFile(t, filepath.Join(directory, "identity.txt"), FormatIdentityFile(identity, ""))
	source := must[IdentitySource](t)(FromCommand([]string{os.Args[0]}, CommandOptions{SourceOptions: SourceOptions{Host: helperHost("cat", "identity.txt"), Cwd: directory}}))
	equal(t, tokens(t, source), identity.PublicKey.Token)
}

func TestAbsoluteSourceSpec(t *testing.T) {
	h := NativeHost()
	cwd := must[string](t)(filepath.Abs(filepath.FromSlash("/work/project")))
	equal(t, AbsoluteSourceSpec(h, "file:identity.txt", cwd), "file:"+filepath.Join(cwd, "identity.txt"))
	equal(t, AbsoluteSourceSpec(h, "./keys/id.txt", cwd), "file:"+filepath.Join(cwd, "keys", "id.txt"))
	equal(t, AbsoluteSourceSpec(h, "~/id.txt", cwd), "~/id.txt")
	equal(t, AbsoluteSourceSpec(h, "file:~/id.txt", cwd), "file:~/id.txt")
	for _, spec := range []string{"op://Private/msecrets/identity", "bw:item", "pass:dev/id", "keychain:work", "env:KEY", "cmd:gopass show x"} {
		equal(t, AbsoluteSourceSpec(h, spec, cwd), spec)
	}
}

func TestFirstLine(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	h := helperHost("print", identity.Secret+"\nurl: https://example.com\nlogin: me\n")
	_, err := must[IdentitySource](t)(FromCommand([]string{os.Args[0]}, CommandOptions{SourceOptions: SourceOptions{Host: h}})).Load()
	expectError(t, err, CodeIdentitySource, "")
	source := must[IdentitySource](t)(FromCommand([]string{os.Args[0]}, CommandOptions{SourceOptions: SourceOptions{Host: h}, FirstLine: true}))
	equal(t, tokens(t, source), identity.PublicKey.Token)
}

func TestWindowsBatchShims(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	directory := t.TempDir()
	identity := must[*Identity](t)(GenerateIdentity(false))
	writeFile(t, filepath.Join(directory, "identity.txt"), identity.Secret)
	writeFile(t, filepath.Join(directory, "fake-pm.cmd"), "@type \""+filepath.Join(directory, "identity.txt")+"\"\r\n")
	env := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	env["PATH"] = directory + ";" + env["PATH"]
	source := must[IdentitySource](t)(FromCommand([]string{"fake-pm", "get", "password", "my item"}, CommandOptions{SourceOptions: SourceOptions{Host: WithEnv(NativeHost(), env), Cwd: directory}}))
	equal(t, tokens(t, source), identity.PublicKey.Token)
}

func TestSourceSpecs(t *testing.T) {
	label := func(spec string) string { return must[IdentitySource](t)(ParseSourceSpec(spec, SourceOptions{})).Label }
	equal(t, label("op://Private/msecrets/identity"), "1Password op://Private/msecrets/identity")
	equal(t, label("bw:msecrets"), "Bitwarden msecrets")
	equal(t, label("pass:dev/msecrets"), "pass dev/msecrets")
	equal(t, label("keychain:work"), "OS keychain (work)")
	equal(t, label("keychain"), "OS keychain (default)")
	equal(t, label("env:MY_KEY"), "env MY_KEY")
	equal(t, label("file:/tmp/key"), "file "+must[string](t)(filepath.Abs("/tmp/key")))
	equal(t, label("~/key.txt"), "file "+filepath.Join(must[string](t)(os.UserHomeDir()), "key.txt"))
	equal(t, label("cmd:gopass show -o msecrets"), "command `gopass show -o msecrets`")
	_, err := ParseSourceSpec("vault:secret", SourceOptions{})
	expectError(t, err, CodeUsage, "")
}

func TestSplitCommandLine(t *testing.T) {
	equal(t, strings.Join(SplitCommandLine(`op read "op://My Vault/item/field"  --no-newline 'a b'`), "|"), "op|read|op://My Vault/item/field|--no-newline|a b")
}

func TestLoadIdentitiesRemovesDuplicates(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	source := func(name string) IdentitySource {
		return IdentitySource{name, func() ([]LoadedIdentity, error) { return []LoadedIdentity{{identity, name}}, nil }}
	}
	loaded := must[[]LoadedIdentity](t)(LoadIdentities([]IdentitySource{source("one"), source("two")}))
	equal(t, len(loaded), 1)
	equal(t, loaded[0].Source, "one")
}

func TestRuntimeVariablesWin(t *testing.T) {
	directory := t.TempDir()
	runtimeIdentity := must[*Identity](t)(GenerateIdentity(false))
	developer := must[*Identity](t)(GenerateIdentity(false))
	writeFile(t, filepath.Join(directory, "identity.txt"), FormatIdentityFile(developer, ""))
	writeFile(t, filepath.Join(directory, "config.json"), `{"identities":[`+jsQuote("file:"+filepath.Join(directory, "identity.txt"))+`]}`)

	equal(t, tokens(t, AutoSource(SourceOptions{Host: emptyEnv(), ConfigDirectory: directory})), developer.PublicKey.Token)
	env := map[string]string{"MSECRETS_IDENTITY": runtimeIdentity.Secret}
	equal(t, tokens(t, AutoSource(SourceOptions{Host: WithEnv(NativeHost(), env), ConfigDirectory: directory})), runtimeIdentity.PublicKey.Token)
	_, present := env["MSECRETS_IDENTITY"]
	equal(t, present, false)
}

func TestIdentityFileWithPassphrase(t *testing.T) {
	directory := t.TempDir()
	identity := must[*Identity](t)(GenerateIdentity(false))
	path := filepath.Join(directory, "identity.age")
	recipient := must[age.Recipient](t)(ScryptRecipient("pw", 10))
	writeFile(t, path, Armor(must[[]byte](t)(EncryptAge([]byte(FormatIdentityFile(identity, "")), []age.Recipient{recipient}))))

	env := map[string]string{"MSECRETS_IDENTITY_FILE": path, "MSECRETS_PASSPHRASE": "pw"}
	equal(t, tokens(t, AutoSource(SourceOptions{Host: WithEnv(NativeHost(), env), ConfigDirectory: directory})), identity.PublicKey.Token)
	_, present := env["MSECRETS_PASSPHRASE"]
	equal(t, present, false)

	_, err := AutoSource(SourceOptions{Host: WithEnv(NativeHost(), map[string]string{"MSECRETS_IDENTITY_FILE": path}), ConfigDirectory: directory}).Load()
	expectError(t, err, CodeIdentitySource, "set MSECRETS_PASSPHRASE")

	viaSpec := WithEnv(NativeHost(), map[string]string{"MSECRETS_IDENTITY_SOURCE": "file:" + path, "MSECRETS_PASSPHRASE": "pw"})
	equal(t, tokens(t, AutoSource(SourceOptions{Host: viaSpec, ConfigDirectory: directory})), identity.PublicKey.Token)
}

func TestSystemdCredentials(t *testing.T) {
	directory := t.TempDir()
	identity := must[*Identity](t)(GenerateIdentity(false))
	writeFile(t, filepath.Join(directory, "msecrets_identity"), identity.Secret)
	h := WithEnv(NativeHost(), map[string]string{"CREDENTIALS_DIRECTORY": directory})
	equal(t, tokens(t, AutoSource(SourceOptions{Host: h, ConfigDirectory: directory})), identity.PublicKey.Token)
}

func TestDefaultIdentityFile(t *testing.T) {
	directory := t.TempDir()
	equal(t, tokens(t, AutoSource(SourceOptions{Host: emptyEnv(), ConfigDirectory: directory})), "")
	identity := must[*Identity](t)(GenerateIdentity(false))
	writeFile(t, filepath.Join(directory, "identity.txt"), identity.Secret)
	equal(t, tokens(t, AutoSource(SourceOptions{Host: emptyEnv(), ConfigDirectory: directory})), identity.PublicKey.Token)
}

func TestInvalidConfig(t *testing.T) {
	directory := t.TempDir()
	config := must[*UserConfig](t)(ReadUserConfig(NativeHost(), directory))
	equal(t, config == nil, true)
	writeFile(t, filepath.Join(directory, "config.json"), "{")
	_, err := ReadUserConfig(NativeHost(), directory)
	expectError(t, err, CodeIdentitySource, `Invalid .*config\.json`)
	writeFile(t, filepath.Join(directory, "config.json"), `{"identities":"keychain"}`)
	_, err = ReadUserConfig(NativeHost(), directory)
	expectError(t, err, CodeIdentitySource, "must be an array")
}

func TestConfigDirectory(t *testing.T) {
	directory := func(platform string, env map[string]string) string {
		return must[string](t)(ConfigDirectory(testHost{WithEnv(NativeHost(), env), platform}))
	}
	equal(t, directory("linux", map[string]string{"MSECRETS_CONFIG_DIR": "/x"}), "/x")
	equal(t, directory("linux", map[string]string{"XDG_CONFIG_HOME": "/xdg"}), filepath.Join("/xdg", "msecrets"))
	equal(t, directory("windows", map[string]string{"APPDATA": `C:\Users\me\AppData\Roaming`}), filepath.Join(`C:\Users\me\AppData\Roaming`, "msecrets"))
	equal(t, directory("darwin", map[string]string{}), filepath.Join(must[string](t)(os.UserHomeDir()), ".config", "msecrets"))
}

func TestKeychainValidation(t *testing.T) {
	_, _, err := ReadKeychain(NativeHost(), "Bad Account")
	expectError(t, err, CodeUsage, "")
	expectError(t, WriteKeychain(NativeHost(), "default", "two\nlines"), CodeUsage, "single-line")
	_, _, err = ReadKeychain(testHost{NativeHost(), "aix"}, "default")
	expectError(t, err, CodeUnsupported, "")
}

func TestRealKeychain(t *testing.T) {
	if os.Getenv("MSECRETS_TEST_KEYCHAIN") == "" {
		t.Skip("set MSECRETS_TEST_KEYCHAIN=1 to run")
	}
	h := NativeHost()
	account := "msecrets-test-go"
	identity := must[*Identity](t)(GenerateIdentity(false))
	defer DeleteKeychain(h, account)
	_, found, err := ReadKeychain(h, account)
	check(t, err)
	equal(t, found, false)
	check(t, WriteKeychain(h, account, identity.Secret))
	equal(t, tokens(t, must[IdentitySource](t)(ParseSourceSpec("keychain:"+account, SourceOptions{}))), identity.PublicKey.Token)
	equal(t, must[bool](t)(DeleteKeychain(h, account)), true)
}
