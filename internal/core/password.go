package core

// Password members: recipients whose private key is derived from a password.
//
// The recipient entry stores an ordinary msecrets1… public key and a random
// salt. The identity is scrypt(password, salt) used as an age secret key (its
// signing key derived as for any identity), so the member needs nothing but
// the password, on any machine. The public key is in the repository, so anyone
// can try to guess the password offline: the work factor is high and passwords
// have a minimum length.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

const (
	passwordInfo = "msecrets/v6/password\n"
	// scrypt N = 2^18, r = 8, p = 1: 256 MiB and about a second per guess.
	passwordWorkFactor = 18
	saltSize           = 16
	// MinPasswordLength is the minimum length of a password, in characters.
	MinPasswordLength = 16
	passwordAlphabet  = "23456789abcdefghijkmnpqrstuvwxyz"
)

// saltProblem describes why salt is not a valid salt for the key (nil if it did not parse), or returns "".
func saltProblem(salt string, key *PublicKey) string {
	decoded, err := base64.StdEncoding.DecodeString(salt)
	if err != nil || len(decoded) != saltSize || base64.StdEncoding.EncodeToString(decoded) != salt {
		return "Expected a base64 16-byte salt"
	}
	if key != nil && (key.SigningKey == nil || key.Kind == KindSSHEd25519) {
		return "Password members have an msecrets1… key"
	}
	return ""
}

// PasswordProblem describes why password cannot be used for a password member, or returns "".
func PasswordProblem(password string) string {
	if !utf8.ValidString(password) || strings.ContainsFunc(password, isControl) {
		return "Passwords must not contain control characters"
	}
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return fmt.Sprintf("Passwords must have at least %d characters, because the public key in the repository lets anyone try to guess them; a generated password is safest", MinPasswordLength)
	}
	return ""
}

// GeneratePassword returns a random password that is easy to type: four groups of five
// lowercase letters and digits, without look-alikes (100 bits).
func GeneratePassword() string {
	random := randomBytes(20)
	defer clear(random)
	groups := make([]string, 4)
	for group := range groups {
		var b strings.Builder
		for _, value := range random[group*5 : group*5+5] {
			b.WriteByte(passwordAlphabet[value%32])
		}
		groups[group] = b.String()
	}
	return strings.Join(groups, "-")
}

func derivePasswordIdentity(kind KeyKind, salt []byte, password string) (*Identity, error) {
	secret, err := scrypt.Key([]byte(password), append([]byte(passwordInfo), salt...), 1<<passwordWorkFactor, 8, 1, 32)
	if err != nil {
		return nil, wrapError(CodeUsage, err, "Cannot derive a key from the password: %v", err)
	}
	defer clear(secret)
	return ageIdentity(kind, secret)
}

// NewPasswordIdentity derives the identity of a new password member from password and
// a fresh salt. Store the salt with the recipient (see [AddPasswordRecipient]).
func NewPasswordIdentity(password string, postQuantum bool) (*Identity, string, error) {
	if problem := PasswordProblem(password); problem != "" {
		return nil, "", newError(CodeUsage, "%s", problem)
	}
	kind := KindX25519
	if postQuantum {
		kind = KindMLKEM768X25519
	}
	salt := make([]byte, saltSize)
	rand.Read(salt)
	identity, err := derivePasswordIdentity(kind, salt, password)
	if err != nil {
		return nil, "", err
	}
	return identity, base64.StdEncoding.EncodeToString(salt), nil
}

// PasswordMembers returns the names of the password members of the document.
func PasswordMembers(document *Document) []string {
	var names []string
	for name, entry := range document.Recipients.All() {
		if entry.Salt != "" {
			names = append(names, name)
		}
	}
	return names
}

// UnlockPassword returns the password member that password belongs to, with its identity.
// name limits the search to that recipient ("" tries every password member).
func UnlockPassword(document *Document, password, name string) (Member, error) {
	candidates := PasswordMembers(document)
	if name != "" {
		entry, err := RequireRecipient(document, name)
		if err != nil {
			return Member{}, err
		}
		if entry.Salt == "" {
			return Member{}, newError(CodeUsage, "\"%s\" is not a password member: its key is not derived from a password", name)
		}
		candidates = []string{name}
	}
	if len(candidates) == 0 {
		return Member{}, newError(CodeNotFound, "This file has no password members")
	}
	for _, candidate := range candidates {
		entry, _ := document.Recipients.Get(candidate)
		key, err := RecipientKey(document, candidate)
		if err != nil {
			return Member{}, err
		}
		salt, _ := base64.StdEncoding.DecodeString(entry.Salt)
		identity, err := derivePasswordIdentity(key.Kind, salt, password)
		if err != nil {
			return Member{}, err
		}
		if IdentityMatches(identity, key) && bytes.Equal(identity.PublicKey.SigningKey, key.SigningKey) {
			return Member{Name: candidate, Identity: identity}, nil
		}
	}
	return Member{}, newError(CodeAccessDenied, "Wrong password for %s", strings.Join(candidates, ", "))
}

// AddPasswordRecipient adds a password member: identity and salt come from [NewPasswordIdentity].
func AddPasswordRecipient(document *Document, name string, identity *Identity, salt, description string) error {
	entry, err := AddRecipient(document, name, identity.PublicKey.Token, description)
	if err != nil {
		return err
	}
	if problem := saltProblem(salt, identity.PublicKey); problem != "" {
		document.Recipients.Delete(name)
		return newError(CodeUsage, "%s", problem)
	}
	entry.Salt = salt
	return nil
}
