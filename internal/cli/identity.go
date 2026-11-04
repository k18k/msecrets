package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/k18k/msecrets/internal/core"
)

func parseStoreTarget(value string) (string, error) {
	switch value {
	case "", "keychain", "file", "print":
		return value, nil
	}
	return "", usageError("Unknown --store \"%s\"; use keychain, file, or print", value)
}

func writePrivateFile(path, text string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = file.WriteString(text)
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	// Mode bits passed to open are subject to the umask; enforce owner-only access.
	return os.Chmod(path, 0o600)
}

func writeUserConfig(directory string, config *core.UserConfig) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(directory, "config.json")
	object := orderedObject{}
	object.add("identities", config.Identities)
	text, err := jsonText(object)
	if err != nil {
		return err
	}
	temporary := fmt.Sprintf("%s.%d.%d.tmp", path, os.Getpid(), time.Now().UnixNano())
	if err := writePrivateFile(temporary, text+"\n"); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return &core.Error{Code: core.CodeIdentitySource, Message: fmt.Sprintf("Failed to write %s: %v", path, err), Cause: err}
	}
	return nil
}

// addIdentitySource adds an identity source spec to the developer config (first position wins).
func addIdentitySource(c *Context, spec string) (string, error) {
	directory, err := core.ConfigDirectory(c.Host)
	if err != nil {
		return "", err
	}
	config, err := core.ReadUserConfig(c.Host, directory)
	if err != nil {
		return "", err
	}
	if config == nil {
		config = &core.UserConfig{Identities: []string{}}
	}
	if !slices.Contains(config.Identities, spec) {
		config.Identities = append(config.Identities, spec)
		if err := writeUserConfig(directory, config); err != nil {
			return "", err
		}
	}
	return filepath.Join(directory, "config.json"), nil
}

// storeIdentity stores a new identity and returns the source spec that loads it ("" when only printed).
func storeIdentity(c *Context, identity *core.Identity, target, account string, passphrase bool) (string, error) {
	if account == "" {
		account = "default"
	}
	if target == "print" {
		_, err := fmt.Fprint(c.Stdout, core.FormatIdentityFile(identity, ""))
		return "", err
	}

	if target == "keychain" || (target == "" && !passphrase) {
		err := func() error {
			// Never replace a stored key: it may be the only copy that decrypts existing secrets.
			_, found, err := core.ReadKeychain(c.Host, account)
			if err != nil {
				return err
			}
			if found {
				return coreError(core.CodeConflict, "The OS keychain already holds an msecrets identity \"%s\". To use it, run `msecrets identity use keychain:%s`; to create another one, pass --account NAME", account, account)
			}
			return core.WriteKeychain(c.Host, account, identity.Secret)
		}()
		if err == nil {
			return "keychain:" + account, nil
		}
		if target == "keychain" || core.IsError(err, core.CodeConflict) {
			return "", err
		}
		c.Note(c.Err.Dim(fmt.Sprintf("OS keychain unavailable (%s); storing the identity in a file instead", err)))
	}

	directory, err := core.ConfigDirectory(c.Host)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	name := core.DefaultIdentityFilename
	if account != "default" {
		name = "identity-" + account + ".txt"
	}
	path := filepath.Join(directory, name)
	text := core.FormatIdentityFile(identity, "")

	if passphrase {
		first, err := c.Ask("New passphrase for the identity file: ", true)
		if err != nil {
			return "", err
		}
		if first == "" {
			return "", usageError("The passphrase must not be empty")
		}
		second, err := c.Ask("Repeat the passphrase: ", true)
		if err != nil {
			return "", err
		}
		if second != first {
			return "", usageError("The passphrases do not match")
		}
		recipient, err := core.ScryptRecipient(first, 0)
		if err != nil {
			return "", err
		}
		encrypted, err := core.EncryptAge([]byte(text), []age.Recipient{recipient})
		if err != nil {
			return "", err
		}
		text = core.Armor(encrypted)
	}

	if err := writePrivateFile(path, text); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return "", &core.Error{Code: core.CodeConflict, Message: path + " already exists; choose another --account", Cause: err}
		}
		return "", err
	}
	return "file:" + path, nil
}

// ensureIdentity uses the first loaded identity, or creates, stores, and configures a new one.
func ensureIdentity(c *Context, target string, postQuantum, passphrase bool) (*core.Identity, error) {
	identities, err := c.Identities()
	if err != nil {
		return nil, err
	}
	if len(identities) > 0 {
		return identities[0], nil
	}
	identity, err := core.GenerateIdentity(postQuantum)
	if err != nil {
		return nil, err
	}
	spec, err := storeIdentity(c, identity, target, "", passphrase)
	if err != nil {
		return nil, err
	}
	if spec == "" {
		c.Note(c.Err.Yellow("Store the identity printed above in your password manager, then run `msecrets identity use <source>`"))
		return identity, nil
	}
	configPath, err := addIdentitySource(c, spec)
	if err != nil {
		return nil, err
	}
	where := strings.TrimPrefix(spec, "file:")
	if strings.HasPrefix(spec, "keychain:") {
		where = "OS keychain"
	}
	c.Success(fmt.Sprintf("Created your identity (%s), registered in %s", where, configPath))
	return identity, nil
}

var (
	nameInvalid  = regexp.MustCompile(`[^a-z0-9._@+-]+`)
	nameEdges    = regexp.MustCompile(`^[^a-z0-9]+|[^a-z0-9]+$`)
	nameTrailing = regexp.MustCompile(`[^a-z0-9]+$`)
)

// defaultRecipientName is a recipient name for the current user: git user.email, else the OS user name.
func defaultRecipientName(cwd string) string {
	var candidates []string
	command := exec.Command("git", "config", "user.email")
	command.Dir = cwd
	if output, err := command.Output(); err == nil {
		candidates = append(candidates, strings.TrimSpace(string(output)))
	}
	if current, err := user.Current(); err == nil {
		candidates = append(candidates, current.Username)
	}
	for _, candidate := range candidates {
		name := nameEdges.ReplaceAllString(nameInvalid.ReplaceAllString(strings.ToLower(candidate), "-"), "")
		if len(name) > 64 {
			name = name[:64]
		}
		name = nameTrailing.ReplaceAllString(name, "")
		if name != "" && core.NameProblem(core.RecipientName, name) == "" {
			return name
		}
	}
	return "me"
}
