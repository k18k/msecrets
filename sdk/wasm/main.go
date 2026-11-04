//go:build js && wasm

// Command wasm is the core of @msecrets/ts-sdk: the JavaScript loader (sdk/js/index.cjs)
// runs it once, main registers the functions below on the bridge object and
// blocks, and every call from JavaScript then runs synchronously.
//
// Go's own os and os/exec packages use asynchronous Node.js callbacks on
// js/wasm and would deadlock inside a synchronous call, so all system access
// goes through host, which calls the synchronous Node.js APIs the loader passes in.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall/js"
	"time"

	"github.com/k18k/msecrets/internal/core"
)

// bridge holds the Node.js modules and helpers from the loader, and receives the exported functions.
var bridge, process js.Value

func main() {
	bridge = js.Global().Get("__msecrets")
	process = js.Global().Get("process")
	exports := map[string]func([]js.Value) (any, error){
		"environment": environment,
		"source":      source,
		"load":        load,
		"reveal":      reveal,
	}
	for name, function := range exports {
		bridge.Set(name, js.FuncOf(func(_ js.Value, args []js.Value) any { return export(function, args) }))
	}
	select {}
}

// export runs a function and returns {value}, or the error as {code, message}, {thrown} (an
// exception of a JavaScript callback, rethrown as is), or {message}.
func export(function func([]js.Value) (any, error), args []js.Value) (result any) {
	defer func() {
		if r := recover(); r != nil {
			result = map[string]any{"message": fmt.Sprint("msecrets internal error: ", r)}
		}
	}()
	value, err := function(args)
	var coreError *core.Error
	var thrown jsError
	switch {
	case err == nil:
		return map[string]any{"value": value}
	case errors.As(err, &coreError):
		return map[string]any{"code": string(coreError.Code), "message": coreError.Message}
	case errors.As(err, &thrown):
		return map[string]any{"thrown": thrown.value}
	}
	return map[string]any{"message": err.Error()}
}

// jsError is an exception thrown by a JavaScript function.
type jsError struct{ value js.Value }

func (e jsError) Error() string {
	if message := e.value.Get("message"); message.Type() == js.TypeString {
		return message.String()
	}
	return js.Global().Call("String", e.value).String()
}

func (e jsError) Is(target error) bool {
	code := e.value.Get("code")
	if code.Type() != js.TypeString {
		return false
	}
	switch target {
	case fs.ErrNotExist:
		return code.String() == "ENOENT" || code.String() == "ENOTDIR"
	case fs.ErrExist:
		return code.String() == "EEXIST"
	}
	return false
}

// call calls a JavaScript function; an exception becomes a jsError instead of a Go panic.
func call(function, this js.Value, args ...any) (js.Value, error) {
	result := bridge.Call("invoke", append([]any{function, this}, args...)...)
	if !result.Get("ok").Bool() {
		return js.Undefined(), jsError{result.Get("error")}
	}
	return result.Get("value"), nil
}

func method(object js.Value, name string, args ...any) (js.Value, error) {
	return call(object.Get(name), object, args...)
}

// asString returns a JavaScript string, or "" for any other value.
func asString(value js.Value) string {
	if value.Type() == js.TypeString {
		return value.String()
	}
	return ""
}

func str(object js.Value, key string) string { return asString(object.Get(key)) }

func anys[T any](list []T) []any {
	result := make([]any, len(list))
	for index, item := range list {
		result[index] = item
	}
	return result
}

func toGo(value js.Value) []byte {
	data := make([]byte, value.Length())
	js.CopyBytesToGo(data, value)
	return data
}

func toJS(data []byte) js.Value {
	array := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(array, data)
	return array
}

// host implements core.Host with synchronous Node.js APIs.
type host struct{}

func (host) LookupEnv(key string) (string, bool) {
	value := process.Get("env").Get(key)
	return asString(value), value.Type() == js.TypeString
}

func (host) Unsetenv(key string) error {
	process.Get("env").Delete(key)
	return nil
}

func (host) Environ() []string {
	entries := js.Global().Get("Object").Call("entries", process.Get("env"))
	environ := make([]string, entries.Length())
	for index := range environ {
		environ[index] = entries.Index(index).Index(0).String() + "=" + entries.Index(index).Index(1).String()
	}
	return environ
}

func (host) ReadFile(path string) ([]byte, error) {
	data, err := method(bridge.Get("fs"), "readFileSync", path)
	if err != nil {
		return nil, err
	}
	return toGo(data), nil
}

func (host) CreateFile(path string, data []byte) error {
	nodeFS := bridge.Get("fs")
	fd, err := method(nodeFS, "openSync", path, "wx", 0o644)
	if err != nil {
		return err
	}
	_, err = method(nodeFS, "writeSync", fd, toJS(data))
	if err == nil {
		_, err = method(nodeFS, "fsyncSync", fd)
	}
	_, closeErr := method(nodeFS, "closeSync", fd)
	return errors.Join(err, closeErr)
}

func (host) Rename(from, to string) error {
	_, err := method(bridge.Get("fs"), "renameSync", from, to)
	return err
}

func (host) Remove(path string) error {
	if _, err := method(bridge.Get("fs"), "unlinkSync", path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

type fileInfo struct {
	name    string
	size    int64
	mode    fs.FileMode
	modTime time.Time
}

func (i fileInfo) Name() string       { return i.name }
func (i fileInfo) Size() int64        { return i.size }
func (i fileInfo) Mode() fs.FileMode  { return i.mode }
func (i fileInfo) ModTime() time.Time { return i.modTime }
func (i fileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i fileInfo) Sys() any           { return nil }

func (host) Stat(path string) (fs.FileInfo, error) {
	stat, err := method(bridge.Get("fs"), "statSync", path)
	if err != nil {
		return nil, err
	}
	mode := fs.FileMode(stat.Get("mode").Int() & 0o777)
	if stat.Call("isDirectory").Bool() {
		mode |= fs.ModeDir
	}
	return fileInfo{filepath.Base(path), int64(stat.Get("size").Float()), mode, time.UnixMilli(int64(stat.Get("mtimeMs").Float()))}, nil
}

func (host) Getwd() (string, error) {
	cwd, err := method(process, "cwd")
	return cwd.String(), err
}

func (host) HomeDir() (string, error) {
	home, err := method(bridge.Get("os"), "homedir")
	return home.String(), err
}

func (host) Platform() string {
	if platform := process.Get("platform").String(); platform != "win32" {
		return platform
	}
	return "windows"
}

func (host) Pid() int { return process.Get("pid").Int() }

func (host) ProcessExists(pid int) bool {
	_, err := method(process, "kill", pid, 0)
	return err == nil || err.(jsError).value.Get("code").Equal(js.ValueOf("EPERM"))
}

// Sleep blocks the thread (Atomics.wait): time.Sleep would wait for the event loop.
func (host) Sleep(duration time.Duration) { bridge.Call("sleep", duration.Milliseconds()) }

func (host) Run(command core.Command) (core.CommandResult, error) {
	env := js.Global().Get("Object").New()
	for _, entry := range command.Env {
		key, value, _ := strings.Cut(entry, "=")
		env.Set(key, value)
	}
	options := map[string]any{
		"env":                      env,
		"windowsHide":              true,
		"windowsVerbatimArguments": command.Verbatim,
		"maxBuffer":                js.Global().Get("Infinity"),
	}
	if command.Interactive {
		options["stdio"] = []any{"inherit", "pipe", "inherit"}
	} else {
		options["input"] = toJS(command.Stdin)
	}
	if command.Dir != "" {
		options["cwd"] = command.Dir
	}
	if command.Timeout > 0 {
		options["timeout"] = command.Timeout.Milliseconds()
	}
	if command.MaxOutput > 0 {
		options["maxBuffer"] = command.MaxOutput
	}
	result, err := method(bridge.Get("childProcess"), "spawnSync", command.Path, anys(command.Args), options)
	if err != nil {
		return core.CommandResult{}, err
	}
	if failure := result.Get("error"); !failure.IsUndefined() {
		return core.CommandResult{}, jsError{failure}
	}
	output := core.CommandResult{Stdout: toGo(result.Get("stdout"))}
	if stderr := result.Get("stderr"); !stderr.IsNull() {
		output.Stderr = toGo(stderr)
	}
	if status := result.Get("status"); status.IsNull() {
		output.ExitCode, output.Signal = -1, result.Get("signal").String()
	} else {
		output.ExitCode = status.Int()
	}
	return output, nil
}

// identitySource interprets a source descriptor from the loader (see sources in index.cjs).
// envPassphrase is shared by the descriptors of one call that unlock with MSECRETS_PASSPHRASE.
func identitySource(descriptor js.Value, envPassphrase *func(string) (string, error)) (core.IdentitySource, error) {
	options := core.SourceOptions{
		Host:            host{},
		NoScrub:         descriptor.Get("scrub").Equal(js.ValueOf(false)),
		ConfigDirectory: str(descriptor, "configDirectory"),
		Cwd:             str(descriptor, "cwd"),
	}
	switch passphrase := descriptor.Get("passphrase"); {
	case passphrase.Type() == js.TypeFunction:
		options.Passphrase = func(label string) (string, error) {
			value, err := call(passphrase, js.Undefined(), label)
			if err == nil && value.Type() != js.TypeString {
				err = &core.Error{Code: core.CodeUsage, Message: "The passphrase function must return a string"}
			}
			return value.String(), err
		}
	case passphrase.Equal(js.ValueOf("env")):
		if *envPassphrase == nil {
			supplier, err := core.PassphraseFromEnv(host{}, true)
			if err != nil {
				return core.IdentitySource{}, err
			}
			*envPassphrase = supplier
		}
		options.Passphrase = *envPassphrase
	}

	switch kind := str(descriptor, "kind"); kind {
	case "string":
		return core.FromString(str(descriptor, "text"), str(descriptor, "label"), options), nil
	case "env":
		return core.FromEnv(str(descriptor, "variable"), options), nil
	case "file":
		return core.FromFile(str(descriptor, "path"), descriptor.Get("optional").Truthy(), options)
	case "command":
		argv := []string{}
		for index := range descriptor.Get("argv").Length() {
			argv = append(argv, asString(descriptor.Get("argv").Index(index)))
		}
		return core.FromCommand(argv, core.CommandOptions{SourceOptions: options, Label: str(descriptor, "label"), FirstLine: descriptor.Get("firstLine").Truthy()})
	case "keychain":
		return core.FromKeychain(str(descriptor, "account"), options), nil
	case "spec":
		return core.ParseSourceSpec(str(descriptor, "spec"), options)
	case "auto":
		return core.AutoSource(options), nil
	default:
		return core.IdentitySource{}, &core.Error{Code: core.CodeUsage, Message: fmt.Sprintf("Unknown identity source kind %q", kind)}
	}
}

// source(descriptor) validates a descriptor and returns its label.
func source(args []js.Value) (any, error) {
	var envPassphrase func(string) (string, error)
	source, err := identitySource(args[0], &envPassphrase)
	return source.Label, err
}

// load(descriptor) loads the identities of a source: [{identity, source}].
func load(args []js.Value) (any, error) {
	var envPassphrase func(string) (string, error)
	source, err := identitySource(args[0], &envPassphrase)
	if err != nil {
		return nil, err
	}
	loaded, err := core.LoadIdentities([]core.IdentitySource{source})
	list := []any{}
	for _, entry := range loaded {
		list = append(list, map[string]any{"identity": entry.Identity.Secret, "source": entry.Source})
	}
	return list, err
}

// applicable parses the file and chooses the environment; it fails unless every secret of
// the environment has a value.
func applicable(text, explicit string) (*core.Document, string, []string, error) {
	document, err := core.ParseDocumentText(text, "")
	if err != nil {
		return nil, "", nil, err
	}
	choice, err := core.ChooseEnvironment(host{}, document, explicit)
	if err != nil {
		return nil, "", nil, err
	}
	names, missing := []string{}, []string{}
	for name, secret := range document.Secrets.All() {
		for _, environment := range core.SecretEnvironments(document, secret) {
			if environment == choice.Name {
				names = append(names, name)
				if !secret.Values.Has(choice.Name) {
					missing = append(missing, name)
				}
			}
		}
	}
	if len(missing) > 0 {
		return nil, "", nil, &core.Error{Code: core.CodeNotFound, Message: fmt.Sprintf("Environment \"%s\" is incomplete; these secrets have no value: %s", choice.Name, strings.Join(missing, ", "))}
	}
	return document, choice.Name, names, nil
}

// environment(fileJSON, env) returns {environment, names}.
func environment(args []js.Value) (any, error) {
	_, name, names, err := applicable(asString(args[0]), asString(args[1]))
	return map[string]any{"environment": name, "names": anys(names)}, err
}

// reveal(fileJSON, environment, descriptors) verifies and decrypts every secret of the environment, in the order of environment().
func reveal(args []js.Value) (any, error) {
	document, name, names, err := applicable(asString(args[0]), asString(args[1]))
	if err != nil {
		return nil, err
	}
	var envPassphrase func(string) (string, error)
	sources := []core.IdentitySource{}
	for index := range args[2].Length() {
		source, err := identitySource(args[2].Index(index), &envPassphrase)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	loaded, err := core.LoadIdentities(sources)
	if err != nil {
		return nil, err
	}
	if len(loaded) == 0 {
		return nil, &core.Error{Code: core.CodeIdentitySource, Message: "No msecrets identity found. Set MSECRETS_IDENTITY (or MSECRETS_IDENTITY_FILE / MSECRETS_IDENTITY_SOURCE), mount /run/secrets/msecrets_identity, or run `msecrets init` on a developer machine"}
	}
	identities := make([]*core.Identity, len(loaded))
	for index, entry := range loaded {
		identities[index] = entry.Identity
	}
	values := []any{}
	for _, secret := range names {
		value, err := core.RevealValue(document, identities, secret, name)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}
