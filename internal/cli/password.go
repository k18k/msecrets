package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/k18k/msecrets/internal/core"
)

var optPassword = option{name: "password", description: "Derive the key from a password that you type when needed, instead of storing a key"}

// askNewPassword asks for a new password twice; an empty answer, or no terminal, generates one
// (generated is true: show it with showGeneratedPassword once the change is saved).
func askNewPassword(c *Context, whose string) (password string, generated bool, err error) {
	if c.StdinTTY {
		first, err := c.Ask(fmt.Sprintf("New password for %s (at least %d characters; Enter generates one): ", whose, core.MinPasswordLength), true)
		if err != nil {
			return "", false, err
		}
		if first != "" {
			if problem := core.PasswordProblem(first); problem != "" {
				return "", false, usageError("%s", problem)
			}
			second, err := c.Ask("Repeat the password: ", true)
			if err != nil {
				return "", false, err
			}
			if second != first {
				return "", false, usageError("The passwords do not match")
			}
			return first, false, nil
		}
	}
	return core.GeneratePassword(), true, nil
}

// showGeneratedPassword prints a generated password to stdout, once.
func showGeneratedPassword(c *Context, password, whose string) {
	c.Print(password)
	c.Note(c.Err.Yellow(fmt.Sprintf("The password of %s above is shown only once. It is the only way to unlock this key: keep it in a password manager.", whose)))
}

// unlockPassword adds the identity of a password member to loaded, when the secrets file has
// password members and none of the loaded keys is a member of it (or --as names a password member).
// The password comes from MSECRETS_PASSPHRASE, else a prompt on a terminal (Enter skips).
func (c *Context) unlockPassword(loaded []core.LoadedIdentity, fromEnv string, haveEnv bool) ([]core.LoadedIdentity, error) {
	if len(c.Options.Identity) > 0 {
		return loaded, nil
	}
	path, err := c.Path()
	if err != nil {
		return loaded, nil
	}
	document, err := core.ReadDocumentFile(c.Host, path)
	if err != nil {
		return loaded, nil
	}
	candidates := core.PasswordMembers(document)
	identities := make([]*core.Identity, len(loaded))
	for index, entry := range loaded {
		identities[index] = entry.Identity
	}
	members, err := core.Members(document, identities)
	if err != nil {
		return nil, err
	}
	only := ""
	if slices.Contains(candidates, c.Options.As) {
		only, candidates = c.Options.As, []string{c.Options.As}
	}
	if len(candidates) == 0 || slices.ContainsFunc(members, func(member core.Member) bool { return only == "" || member.Name == only }) {
		return loaded, nil
	}

	password := fromEnv
	if !haveEnv {
		if !c.StdinTTY {
			return loaded, nil
		}
		password, err = c.Ask(fmt.Sprintf("Password for %s (%s; Enter skips): ", c.DisplayPath(path), strings.Join(candidates, ", ")), true)
		if err != nil || password == "" {
			return loaded, err
		}
	}
	member, err := core.UnlockPassword(document, password, only)
	if err != nil {
		return nil, err
	}
	c.Note(c.Err.Dim(fmt.Sprintf("Unlocked password member \"%s\"", member.Name)))
	return append(loaded, core.LoadedIdentity{Identity: member.Identity, Source: "password of \"" + member.Name + "\""}), nil
}

// newMember is the key a person joins a secrets file with; salt is set for a password member.
type newMember struct {
	identity *core.Identity
	salt     string
	password string
	// generated is set when password was generated, to be shown once.
	generated bool
}

// addMember adds the person as recipient name.
func addMember(document *core.Document, name string, member newMember) error {
	if member.salt != "" {
		return core.AddPasswordRecipient(document, name, member.identity, member.salt, "")
	}
	_, err := core.AddRecipient(document, name, member.identity.PublicKey.Token, "")
	return err
}

// finishMember shows a generated password, after the member was saved.
func finishMember(c *Context, member newMember, name string) {
	if member.generated {
		showGeneratedPassword(c, member.password, "\""+name+"\"")
	}
	if member.salt != "" {
		c.Note(c.Err.Dim("You are a password member: msecrets asks for the password when it needs your key (or reads MSECRETS_PASSPHRASE); nothing is stored on this machine."))
	}
}

// storeChoices are the answers to chooseStore, in order.
var storeChoices = []struct{ store, label string }{
	{"keychain", "a new key in the OS keychain (falls back to a private key file)"},
	{"file", "a new key file, protected by a passphrase"},
	{"password", "a password you type when needed: no key is stored on this machine"},
	{"print", "a new key printed once, to keep in your password manager"},
}

// chooseStore asks where a new key should live, on a terminal; without one it keeps the default.
func chooseStore(c *Context) (store string, passphrase bool, err error) {
	if !c.StdinTTY {
		return "", false, nil
	}
	lines := []string{"You have no msecrets key yet. How do you want to unlock secrets?"}
	for index, choice := range storeChoices {
		lines = append(lines, fmt.Sprintf("  %d) %s", index+1, choice.label))
	}
	c.Note(strings.Join(lines, "\n"))
	answer, err := c.Ask("Choose [1]: ", false)
	if err != nil {
		return "", false, err
	}
	switch strings.TrimSpace(answer) {
	case "", "1":
		return "keychain", false, nil
	case "2":
		return "file", true, nil
	case "3":
		return "password", false, nil
	case "4":
		return "print", false, nil
	}
	return "", false, usageError("Choose 1, 2, 3, or 4")
}
