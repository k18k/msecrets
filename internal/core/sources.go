package core

// Identity sources: where private keys come from at runtime.
//
// Sources never come from the committed secrets file (that would let a
// repository run commands); they come from code, environment variables, or the
// developer's own config file.

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// LoadedIdentity is an identity and where it came from.
type LoadedIdentity struct {
	Identity *Identity
	// Source describes where the identity came from (never contains secret material).
	Source string
}

// IdentitySource loads identities on demand.
type IdentitySource struct {
	Label string
	Load  func() ([]LoadedIdentity, error)
}

// SourceOptions configures identity sources.
type SourceOptions struct {
	// Host provides the environment, files, and processes (nil: NativeHost()).
	Host Host
	// Passphrase supplies passphrases for encrypted identity files and SSH keys.
	Passphrase func(label string) (string, error)
	// NoScrub keeps identity variables in the environment after reading them.
	NoScrub bool
	// ConfigDirectory overrides the developer config directory (see [ConfigDirectory]).
	ConfigDirectory string
	// Cwd resolves relative paths and runs commands ("" for the working directory).
	Cwd string
}

func (options SourceOptions) host() Host {
	if options.Host == nil {
		return NativeHost()
	}
	return options.Host
}

// Environment variables and file names of the identity chain.
const (
	IdentityVariable        = "MSECRETS_IDENTITY"
	IdentityFileVariable    = "MSECRETS_IDENTITY_FILE"
	IdentitySourceVariable  = "MSECRETS_IDENTITY_SOURCE"
	PassphraseVariable      = "MSECRETS_PASSPHRASE"
	ContainerIdentityName   = "msecrets_identity"
	DefaultIdentityFilename = "identity.txt"
)

func parseSource(contents []byte, label string, options SourceOptions) ([]LoadedIdentity, error) {
	var identityOptions IdentityOptions
	if options.Passphrase != nil {
		identityOptions.Passphrase = func() (string, error) { return options.Passphrase(label) }
	}
	identities, err := ParseIdentities(contents, identityOptions)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			code := e.Code
			if code == CodeInvalidKey {
				code = CodeIdentitySource
			}
			return nil, wrapError(code, err, "%s: %s", label, e.Message)
		}
		return nil, err
	}
	loaded := make([]LoadedIdentity, len(identities))
	for index, identity := range identities {
		loaded[index] = LoadedIdentity{identity, label}
	}
	return loaded, nil
}

// PassphraseFromEnv returns a passphrase supplier backed by MSECRETS_PASSPHRASE,
// read now and scrubbed from the environment unless scrub is false.
func PassphraseFromEnv(h Host, scrub bool) (func(label string) (string, error), error) {
	passphrase, ok := h.LookupEnv(PassphraseVariable)
	if scrub {
		if err := h.Unsetenv(PassphraseVariable); err != nil {
			return nil, err
		}
	}
	return func(label string) (string, error) {
		if !ok {
			return "", newError(CodeIdentitySource, "%s is passphrase-protected; set %s", label, PassphraseVariable)
		}
		return passphrase, nil
	}, nil
}

// FromString reads identities from text.
func FromString(text, label string, options SourceOptions) IdentitySource {
	if label == "" {
		label = "inline identity"
	}
	return IdentitySource{label, func() ([]LoadedIdentity, error) { return parseSource([]byte(text), label, options) }}
}

// FromEnv reads identities from an environment variable ("" for MSECRETS_IDENTITY)
// and, unless NoScrub is set, deletes it so child processes never see it.
func FromEnv(variable string, options SourceOptions) IdentitySource {
	if variable == "" {
		variable = IdentityVariable
	}
	label := "env " + variable
	return IdentitySource{label, func() ([]LoadedIdentity, error) {
		h := options.host()
		text, _ := h.LookupEnv(variable)
		if !options.NoScrub {
			if err := h.Unsetenv(variable); err != nil {
				return nil, err
			}
		}
		if jsTrim(text) == "" {
			return nil, nil
		}
		return parseSource([]byte(text), label, options)
	}}
}

var homePrefix = regexp.MustCompile(`^~(?:[\\/]|$)`)

func expandHome(h Host, path string) (string, error) {
	if !homePrefix.MatchString(path) {
		return path, nil
	}
	home, err := h.HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, path[1:]), nil
}

// FromFile reads identities from a file; a missing optional file yields none.
func FromFile(path string, optional bool, options SourceOptions) (IdentitySource, error) {
	h := options.host()
	cwd, err := workingDirectory(h, options.Cwd)
	if err != nil {
		return IdentitySource{}, err
	}
	expanded, err := expandHome(h, path)
	if err != nil {
		return IdentitySource{}, err
	}
	fullPath := resolvePath(h, cwd, expanded)
	label := "file " + fullPath
	return IdentitySource{label, func() ([]LoadedIdentity, error) {
		contents, err := h.ReadFile(fullPath)
		if err != nil {
			if optional && errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			}
			return nil, wrapError(CodeIdentitySource, err, "%s: %v", label, err)
		}
		// Bytes, not text: a passphrase-protected identity file may be binary age.
		return parseSource(contents, label, options)
	}}, nil
}

// CommandOptions configures [FromCommand].
type CommandOptions struct {
	SourceOptions
	// Label names the source ("" for "command `…`").
	Label string
	// FirstLine keeps only the first line of the output (pass keeps metadata below the secret).
	FirstLine bool
}

const (
	commandTimeout   = 120 * time.Second
	commandMaxOutput = 1024 * 1024
)

// FromCommand runs a command (a password manager CLI) whose standard output is the identity.
func FromCommand(argv []string, options CommandOptions) (IdentitySource, error) {
	if len(argv) == 0 || argv[0] == "" {
		return IdentitySource{}, newError(CodeUsage, "An identity command must not be empty")
	}
	label := options.Label
	if label == "" {
		label = "command `" + strings.Join(argv, " ") + "`"
	}
	return IdentitySource{label, func() ([]LoadedIdentity, error) {
		h := options.host()
		cwd, err := workingDirectory(h, options.Cwd)
		if err != nil {
			return nil, err
		}
		plan, err := PlanCommand(h, argv, cwd)
		if err != nil {
			return nil, err
		}
		result, err := h.Run(Command{
			Path:        plan.File,
			Args:        plan.Args,
			Env:         h.Environ(),
			Dir:         options.Cwd,
			Interactive: true, // Password managers may prompt for unlock on the terminal.
			Timeout:     commandTimeout,
			MaxOutput:   commandMaxOutput,
			Verbatim:    plan.Verbatim,
		})
		if errors.Is(err, fs.ErrNotExist) {
			return nil, wrapError(CodeIdentitySource, err, "%s: `%s` is not installed or not on PATH", label, argv[0])
		}
		if err != nil {
			return nil, wrapError(CodeIdentitySource, err, "%s failed: %v", label, err)
		}
		if result.ExitCode != 0 {
			status := fmt.Sprint(result.ExitCode)
			if result.Signal != "" {
				status = result.Signal
			}
			return nil, newError(CodeIdentitySource, "%s failed (exit code %s)", label, status)
		}
		output := result.Stdout
		defer clear(output)
		if options.FirstLine {
			first, _, _ := bytes.Cut(output, []byte("\n"))
			output = bytes.TrimSuffix(first, []byte("\r"))
		}
		return parseSource(output, label, options.SourceOptions)
	}}, nil
}

// FromKeychain reads the identity stored in the OS keychain under an account ("" for "default").
func FromKeychain(account string, options SourceOptions) IdentitySource {
	if account == "" {
		account = "default"
	}
	label := "OS keychain (" + account + ")"
	return IdentitySource{label, func() ([]LoadedIdentity, error) {
		secret, found, err := ReadKeychain(options.host(), account)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, newError(CodeIdentitySource, "%s: no msecrets identity stored for account \"%s\"", label, account)
		}
		return parseSource([]byte(secret), label, SourceOptions{})
	}}
}

var commandLineToken = regexp.MustCompile(`"([^"]*)"|'([^']*)'|(\S+)`)

// SplitCommandLine splits a command line on whitespace, honoring single and double quotes.
func SplitCommandLine(line string) []string {
	tokens := []string{}
	for _, match := range commandLineToken.FindAllStringSubmatchIndex(line, -1) {
		for group := 1; group <= 3; group++ {
			if match[2*group] >= 0 {
				tokens = append(tokens, line[match[2*group]:match[2*group+1]])
				break
			}
		}
	}
	return tokens
}

var relativePath = regexp.MustCompile(`^(?:\.{1,2}[\\/]|~(?:[\\/]|$))`)

func looksLikePath(h Host, spec string) bool {
	return isAbsolute(h, spec) || relativePath.MatchString(spec)
}

// ParseSourceSpec parses an identity source spec:
//   - env:NAME, file:PATH (or a bare path), keychain:ACCOUNT
//   - op://vault/item/field (1Password), bw:ITEM (Bitwarden), pass:NAME (pass)
//   - cmd:COMMAND ARGS… (any command printing the identity)
func ParseSourceSpec(spec string, options SourceOptions) (IdentitySource, error) {
	h := options.host()
	trimmed := jsTrim(spec)
	scheme, value, _ := strings.Cut(trimmed, ":")

	if strings.HasPrefix(trimmed, "op://") {
		return FromCommand([]string{"op", "read", "--no-newline", trimmed}, CommandOptions{SourceOptions: options, Label: "1Password " + trimmed})
	}
	if looksLikePath(h, trimmed) {
		return FromFile(trimmed, false, options)
	}
	switch scheme {
	case "env":
		return FromEnv(value, options), nil
	case "file":
		return FromFile(value, false, options)
	case "keychain":
		return FromKeychain(value, options), nil
	case "bw":
		return FromCommand([]string{"bw", "get", "password", value}, CommandOptions{SourceOptions: options, Label: "Bitwarden " + value})
	case "pass":
		return FromCommand([]string{"pass", "show", value}, CommandOptions{SourceOptions: options, Label: "pass " + value, FirstLine: true})
	case "cmd":
		return FromCommand(SplitCommandLine(value), CommandOptions{SourceOptions: options})
	}
	return IdentitySource{}, newError(CodeUsage, "Unknown identity source \"%s\"; use env:, file:, keychain:, op://, bw:, pass:, cmd:, or a path", sanitize(trimmed))
}

// AbsoluteSourceSpec makes a source spec independent of the working directory,
// for the user config: relative file paths become absolute. Other specs are unchanged.
func AbsoluteSourceSpec(h Host, spec, cwd string) string {
	trimmed := jsTrim(spec)
	path, isFile := strings.CutPrefix(trimmed, "file:")
	if !isFile && (strings.HasPrefix(trimmed, "op://") || !looksLikePath(h, trimmed)) {
		return trimmed
	}
	if homePrefix.MatchString(path) {
		return trimmed
	}
	return "file:" + resolvePath(h, cwd, path)
}

// UserConfig is the developer configuration (config.json in [ConfigDirectory]).
type UserConfig struct {
	// Identities are identity source specs, tried in order.
	Identities []string
}

// ConfigDirectory returns the developer config directory: MSECRETS_CONFIG_DIR,
// else %APPDATA%\msecrets on Windows, else $XDG_CONFIG_HOME/msecrets or ~/.config/msecrets.
func ConfigDirectory(h Host) (string, error) {
	if directory := getenv(h, "MSECRETS_CONFIG_DIR"); directory != "" {
		return directory, nil
	}
	if appData := getenv(h, "APPDATA"); h.Platform() == "windows" && appData != "" {
		return filepath.Join(appData, "msecrets"), nil
	}
	if xdg := getenv(h, "XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "msecrets"), nil
	}
	home, err := h.HomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "msecrets"), nil
}

// ReadUserConfig reads config.json in directory; it returns nil if there is none.
func ReadUserConfig(h Host, directory string) (*UserConfig, error) {
	path := filepath.Join(directory, "config.json")
	text, err := h.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json, err := ParseJSON(string(text))
	if err != nil {
		return nil, wrapError(CodeIdentitySource, err, "Invalid %s: %v", path, err)
	}
	invalid := newError(CodeIdentitySource, "Invalid %s: \"identities\" must be an array of identity source strings", path)
	object, _ := json.(*Map[any])
	if object == nil {
		return nil, invalid
	}
	list, _ := object.Get("identities")
	entries, ok := list.([]any)
	if !ok {
		return nil, invalid
	}
	config := &UserConfig{Identities: []string{}}
	for _, entry := range entries {
		spec, ok := entry.(string)
		if !ok {
			return nil, invalid
		}
		config.Identities = append(config.Identities, spec)
	}
	return config, nil
}

func loadAll(sources []IdentitySource) ([]LoadedIdentity, error) {
	var loaded []LoadedIdentity
	for _, source := range sources {
		identities, err := source.Load()
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, identities...)
	}
	return loaded, nil
}

// AutoSource is the default identity chain.
//
//  1. Explicit runtime configuration: MSECRETS_IDENTITY, MSECRETS_IDENTITY_FILE,
//     MSECRETS_IDENTITY_SOURCE, and container secrets (/run/secrets/msecrets_identity,
//     $CREDENTIALS_DIRECTORY/msecrets_identity).
//  2. Only if none of those yields an identity: the developer config
//     (identities in config.json), or else the default identity file.
func AutoSource(options SourceOptions) IdentitySource {
	return IdentitySource{"default identity sources", func() ([]LoadedIdentity, error) {
		h := options.host()
		shared := options
		shared.Host = h
		if shared.Passphrase == nil {
			passphrase, err := PassphraseFromEnv(h, !options.NoScrub)
			if err != nil {
				return nil, err
			}
			shared.Passphrase = passphrase
		}

		runtime := []IdentitySource{FromEnv(IdentityVariable, shared)}
		add := func(source IdentitySource, err error) error {
			if err == nil {
				runtime = append(runtime, source)
			}
			return err
		}
		if path := getenv(h, IdentityFileVariable); path != "" {
			if err := add(FromFile(path, false, shared)); err != nil {
				return nil, err
			}
		}
		if spec := getenv(h, IdentitySourceVariable); spec != "" {
			if err := add(ParseSourceSpec(spec, shared)); err != nil {
				return nil, err
			}
		}
		if h.Platform() != "windows" {
			if err := add(FromFile("/run/secrets/"+ContainerIdentityName, true, shared)); err != nil {
				return nil, err
			}
		}
		if directory := getenv(h, "CREDENTIALS_DIRECTORY"); directory != "" {
			if err := add(FromFile(filepath.Join(directory, ContainerIdentityName), true, shared)); err != nil {
				return nil, err
			}
		}

		fromRuntime, err := loadAll(runtime)
		if err != nil || len(fromRuntime) > 0 {
			return fromRuntime, err
		}

		directory := options.ConfigDirectory
		if directory == "" {
			if directory, err = ConfigDirectory(h); err != nil {
				return nil, err
			}
		}
		config, err := ReadUserConfig(h, directory)
		if err != nil {
			return nil, err
		}
		if config != nil {
			sources := make([]IdentitySource, len(config.Identities))
			for index, spec := range config.Identities {
				if sources[index], err = ParseSourceSpec(spec, shared); err != nil {
					return nil, err
				}
			}
			return loadAll(sources)
		}
		source, err := FromFile(filepath.Join(directory, DefaultIdentityFilename), true, shared)
		if err != nil {
			return nil, err
		}
		return source.Load()
	}}
}

// LoadIdentities loads every source; a key configured twice is kept once (its first occurrence).
func LoadIdentities(sources []IdentitySource) ([]LoadedIdentity, error) {
	loaded, err := loadAll(sources)
	if err != nil {
		return nil, err
	}
	var unique []LoadedIdentity
	for _, entry := range loaded {
		duplicate := false
		for _, other := range unique {
			duplicate = duplicate || bytes.Equal(other.Identity.PublicKey.EncryptionKey, entry.Identity.PublicKey.EncryptionKey)
		}
		if !duplicate {
			unique = append(unique, entry)
		}
	}
	return unique, nil
}
