package core

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"filippo.io/age"
)

// MaxStanzas bounds the recipient stanzas of an age file (and the recipients of an environment).
const MaxStanzas = 1024

const (
	maxHeaderSize = 1024 * 1024
	ageVersion    = "age-encryption.org/v1"
	armorBegin    = "-----BEGIN AGE ENCRYPTED FILE-----"
	armorEnd      = "-----END AGE ENCRYPTED FILE-----"
)

// SupportsMlKem reports whether post-quantum (ML-KEM-768) keys are available. Always true in Go.
func SupportsMlKem() bool { return true }

// plainRecipient hides the labels of a recipient, so that post-quantum and
// classical recipients can share a file, as in the TypeScript implementation.
type plainRecipient struct{ age.Recipient }

// checkedIdentity applies the header rules of the TypeScript implementation
// that age only enforces for some identities, and keeps the caller's order of
// identities (age tries its native identities first).
type checkedIdentity struct{ identity age.Identity }

func (i checkedIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	for _, stanza := range stanzas {
		if stanza.Type == "scrypt" && len(stanzas) != 1 {
			return nil, newError(CodeAgeHeader, "Invalid age header: an scrypt stanza must be the only stanza")
		}
	}
	if i.identity == nil {
		return nil, age.ErrIncorrectIdentity
	}
	return i.identity.Unwrap(stanzas)
}

// EncryptAge encrypts plaintext to the recipients as a binary age file.
func EncryptAge(plaintext []byte, recipients []age.Recipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, newError(CodeUsage, "At least one recipient is required to encrypt")
	}
	if len(recipients) > MaxStanzas {
		return nil, newError(CodeUsage, "An age file can have at most %d recipients", MaxStanzas)
	}
	plain := make([]age.Recipient, len(recipients))
	for index, recipient := range recipients {
		if _, ok := recipient.(*age.ScryptRecipient); ok && len(recipients) > 1 {
			return nil, newError(CodeUsage, "A passphrase recipient cannot be combined with other recipients")
		}
		plain[index] = plainRecipient{recipient}
	}
	var out bytes.Buffer
	writer, err := age.Encrypt(&out, plain...)
	if err == nil {
		_, err = writer.Write(plaintext)
	}
	if err == nil {
		err = writer.Close()
	}
	if err != nil {
		return nil, wrapError(CodeAgeHeader, err, "Invalid age header: %v", err)
	}
	return out.Bytes(), nil
}

// DecryptAge decrypts a binary age file, or an ASCII-armored one (anything
// not starting with the binary version line that contains "-----").
func DecryptAge(data []byte, identities []age.Identity) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte("age-encryption.org/")) && bytes.Contains(data, []byte("-----")) {
		var err error
		if data, err = Dearmor(string(data)); err != nil {
			return nil, err
		}
	}
	if end := bytes.Index(data, []byte("\n---")); end >= maxHeaderSize || (end < 0 && len(data) > maxHeaderSize) {
		return nil, newError(CodeAgeHeader, "Invalid age header: larger than 1 MiB")
	}

	checked := make([]age.Identity, 0, len(identities)+1)
	for _, identity := range identities {
		checked = append(checked, checkedIdentity{identity})
	}
	if len(checked) == 0 {
		checked = append(checked, checkedIdentity{})
	}

	reader, err := age.Decrypt(bytes.NewReader(data), checked...)
	if err != nil {
		var noMatch *age.NoIdentityMatchError
		var coreError *Error
		switch {
		case errors.As(err, &coreError):
			return nil, coreError
		case errors.As(err, &noMatch):
			return nil, wrapError(CodeAgeNoMatch, err, "No identity matched any of the recipients of this age file")
		case err.Error() == "bad header MAC":
			return nil, wrapError(CodeAgeHMAC, err, "The age header MAC does not match")
		}
		return nil, wrapError(CodeAgeHeader, err, "Invalid age header: %v", err)
	}
	plaintext, err := io.ReadAll(reader)
	if err != nil {
		clear(plaintext)
		return nil, wrapError(CodeAgePayload, err, "Invalid age payload: %v", err)
	}
	return plaintext, nil
}

// ScryptRecipient returns a passphrase recipient with the given work factor (log2 of N; 18 if 0).
func ScryptRecipient(passphrase string, workFactor int) (age.Recipient, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, wrapError(CodeAgeHeader, err, "Invalid age header: passphrase must not be empty")
	}
	if workFactor != 0 {
		recipient.SetWorkFactor(workFactor)
	}
	return recipient, nil
}

// ScryptIdentity returns a passphrase identity (maximum work factor 22).
func ScryptIdentity(passphrase string) (age.Identity, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, wrapError(CodeAgeHeader, err, "Invalid age header: passphrase must not be empty")
	}
	return identity, nil
}

// Armor encodes an age file in strict PEM (RFC 7468) with the "AGE ENCRYPTED FILE" label.
func Armor(data []byte) string {
	encoded := base64.StdEncoding.EncodeToString(data)
	lines := []string{armorBegin}
	for len(encoded) > 64 {
		lines = append(lines, encoded[:64])
		encoded = encoded[64:]
	}
	if encoded != "" {
		lines = append(lines, encoded)
	}
	return strings.Join(append(lines, armorEnd, ""), "\n")
}

// Dearmor decodes an armored age file, rejecting non-canonical encodings.
func Dearmor(text string) ([]byte, error) {
	lines := strings.Split(strings.Trim(text, " \t\r\n"), "\n")
	for index, line := range lines {
		lines[index] = strings.TrimSuffix(line, "\r")
	}
	if lines[0] != armorBegin {
		return nil, newError(CodeAgeArmor, "Invalid age armor: missing begin line")
	}
	if lines[len(lines)-1] != armorEnd || len(lines) < 2 {
		return nil, newError(CodeAgeArmor, "Invalid age armor: missing end line")
	}
	body := lines[1 : len(lines)-1]
	for index, line := range body {
		last := index == len(body)-1
		if line == "" || !containsOnly(line, base64Alphabet+"=") ||
			len(line) > 64 || (!last && len(line) != 64) {
			return nil, newError(CodeAgeArmor, "Invalid age armor: invalid line %d", index+2)
		}
	}
	encoded := strings.Join(body, "")
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(data) != encoded {
		return nil, newError(CodeAgeArmor, "Invalid age armor: non-canonical base64")
	}
	return data, nil
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func containsOnly(text, characters string) bool {
	for i := 0; i < len(text); i++ {
		if strings.IndexByte(characters, text[i]) < 0 {
			return false
		}
	}
	return true
}
