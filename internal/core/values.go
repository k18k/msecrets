package core

// Sealing and opening of secret values.
//
// Every value is age-encrypted to the recipients of its environment and signed
// by a recipient of that environment. The signature binds the ciphertext to the
// file id, secret name, environment, and recipient set, so ciphertext cannot be
// swapped between slots or injected by someone who is not a member.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"sync"

	"filippo.io/age"
)

var publicKeyCache sync.Map // token -> *PublicKey

// RecipientKey parses (and caches) the public key of a named recipient.
func RecipientKey(document *Document, name string) (*PublicKey, error) {
	entry, ok := document.Recipients.Get(name)
	if !ok {
		return nil, newError(CodeNotFound, "Recipient \"%s\" does not exist", name)
	}
	if key, ok := publicKeyCache.Load(entry.Key); ok {
		return key.(*PublicKey), nil
	}
	key, err := ParsePublicKey(entry.Key)
	if err != nil {
		return nil, err
	}
	publicKeyCache.Store(entry.Key, key)
	return key, nil
}

// EnvironmentRecipients returns the recipient names of an environment.
func EnvironmentRecipients(document *Document, environment string) ([]string, error) {
	entry, ok := document.Environments.Get(environment)
	if !ok {
		return nil, newError(CodeNotFound, "Environment \"%s\" does not exist", environment)
	}
	return entry.Recipients, nil
}

func environmentKeys(document *Document, environment string) ([]*PublicKey, error) {
	names, err := EnvironmentRecipients(document, environment)
	if err != nil {
		return nil, err
	}
	keys := make([]*PublicKey, len(names))
	for index, name := range names {
		if keys[index], err = RecipientKey(document, name); err != nil {
			return nil, err
		}
	}
	return keys, nil
}

// RecipientDigest is the digest of a set of recipient keys, independent of order and token form.
func RecipientDigest(keys []*PublicKey) string {
	lines := make([]string, len(keys))
	for index, key := range keys {
		lines[index] = key.id()
	}
	slices.Sort(lines)
	lines = slices.Compact(lines)
	digest := sha256.Sum256([]byte("msecrets/v4/recipients\n" + strings.Join(lines, "\n")))
	return hex.EncodeToString(digest[:16])
}

// EnvironmentDigest is the digest of the current recipients of an environment.
func EnvironmentDigest(document *Document, environment string) (string, error) {
	keys, err := environmentKeys(document, environment)
	if err != nil {
		return "", err
	}
	return RecipientDigest(keys), nil
}

func signatureMessage(document *Document, secret, environment, to, data string) []byte {
	digest := sha256.Sum256([]byte(data))
	return []byte(strings.Join([]string{"msecrets/v4/value", document.ID, secret, environment, to, hex.EncodeToString(digest[:])}, "\n"))
}

// Member is a recipient of the document whose private key is loaded.
type Member struct {
	Name     string
	Identity *Identity
}

// Members returns the recipients of the document whose private keys are among the identities.
func Members(document *Document, identities []*Identity) ([]Member, error) {
	var members []Member
	for _, name := range document.Recipients.keys {
		key, err := RecipientKey(document, name)
		if err != nil {
			return nil, err
		}
		for _, identity := range identities {
			if IdentityMatches(identity, key) {
				members = append(members, Member{Name: name, Identity: identity})
				break
			}
		}
	}
	return members, nil
}

func memberNames(members []Member) []string {
	names := make([]string, len(members))
	for index, member := range members {
		names[index] = member.Name
	}
	return names
}

func orNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

// SignerFor picks the member that signs writes to an environment: a recipient of
// the environment with a signing-capable key (preferred, if not "", must be it).
func SignerFor(document *Document, identities []*Identity, environment, preferred string) (Member, error) {
	allowed, err := EnvironmentRecipients(document, environment)
	if err != nil {
		return Member{}, err
	}
	members, err := Members(document, identities)
	if err != nil {
		return Member{}, err
	}
	for _, member := range members {
		key, err := RecipientKey(document, member.Name)
		if err != nil {
			return Member{}, err
		}
		if slices.Contains(allowed, member.Name) && key.SigningKey != nil && (preferred == "" || member.Name == preferred) {
			return member, nil
		}
	}

	who := "none of your loaded keys is"
	if preferred != "" {
		who = "\"" + preferred + "\" is not"
	} else if len(members) > 0 {
		who = "none of your keys (" + strings.Join(memberNames(members), ", ") + ") is"
	}
	return Member{}, newError(CodeAccessDenied,
		"Cannot write to environment \"%s\": %s a recipient of it with a signing key (msecrets1… or ssh-ed25519). Recipients of \"%s\": %s",
		environment, who, environment, orNone(allowed))
}

// SealValue encrypts plaintext to the recipients of the environment and signs it.
func SealValue(document *Document, secret, environment string, plaintext []byte, signer Member) (*SealedValue, error) {
	keys, err := environmentKeys(document, environment)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, newError(CodeAccessDenied, "Environment \"%s\" has no recipients", environment)
	}
	recipients := make([]age.Recipient, len(keys))
	for index, key := range keys {
		recipients[index] = key.Recipient
	}
	encrypted, err := EncryptAge(plaintext, recipients)
	if err != nil {
		return nil, err
	}
	value := &SealedValue{To: RecipientDigest(keys), Data: base64.StdEncoding.EncodeToString(encrypted)}
	return ResignValue(document, secret, environment, value, signer), nil
}

// ResignValue signs an existing ciphertext for a (possibly renamed) slot.
// Callers must verify the previous signature first.
func ResignValue(document *Document, secret, environment string, value *SealedValue, signer Member) *SealedValue {
	signature := signer.Identity.Sign(signatureMessage(document, secret, environment, value.To, value.Data))
	return &SealedValue{To: value.To, By: signer.Name, Sig: base64.StdEncoding.EncodeToString(signature), Data: value.Data}
}

// SignatureProblem explains why a sealed value cannot be trusted, or returns "" when its signature is valid.
func SignatureProblem(document *Document, secret, environment string, value *SealedValue) (string, error) {
	if !document.Recipients.Has(value.By) {
		return "signed by unknown recipient \"" + value.By + "\"", nil
	}
	allowed, err := EnvironmentRecipients(document, environment)
	if err != nil {
		return "", err
	}
	if !slices.Contains(allowed, value.By) {
		return "signed by \"" + value.By + "\", who is not a recipient of \"" + environment + "\"", nil
	}
	key, err := RecipientKey(document, value.By)
	if err != nil {
		return "", err
	}
	if key.SigningKey == nil {
		return "signed by \"" + value.By + "\", whose key cannot sign", nil
	}
	signature, err := base64.StdEncoding.DecodeString(value.Sig)
	if err != nil || !ed25519.Verify(key.SigningKey, signatureMessage(document, secret, environment, value.To, value.Data), signature) {
		return "the signature by \"" + value.By + "\" does not match (the value was modified, moved, or the signer's key changed)", nil
	}
	return "", nil
}

// OpenValue verifies the signature of a value and decrypts it.
func OpenValue(document *Document, secret, environment string, value *SealedValue, identities []*Identity) ([]byte, error) {
	problem, err := SignatureProblem(document, secret, environment, value)
	if err != nil {
		return nil, err
	}
	if problem != "" {
		return nil, newError(CodeSignature, "Refusing to decrypt %s in \"%s\": %s", secret, environment, problem)
	}

	data, err := base64.StdEncoding.DecodeString(value.Data)
	if err != nil {
		return nil, wrapError(CodeAgeHeader, err, "Invalid age header: not an age file")
	}
	ageIdentities := make([]age.Identity, len(identities))
	for index, identity := range identities {
		ageIdentities[index] = identity.AgeIdentity
	}
	plaintext, err := DecryptAge(data, ageIdentities)
	if !IsError(err, CodeAgeNoMatch) {
		return plaintext, err
	}

	members, memberErr := Members(document, identities)
	if memberErr != nil {
		return nil, memberErr
	}
	allowed, _ := EnvironmentRecipients(document, environment)
	loaded := memberNames(members)
	you := "None of your loaded keys belongs to a recipient of this file."
	if len(loaded) > 0 {
		you = "You are: " + strings.Join(loaded, ", ") + "."
	}
	stale := ""
	if slices.ContainsFunc(loaded, func(name string) bool { return slices.Contains(allowed, name) }) {
		stale = " The value is out of date for you; ask a member to run `msecrets sync`."
	}
	return nil, &Error{
		Code:    CodeAccessDenied,
		Message: "None of your keys can decrypt " + secret + " in \"" + environment + "\". " + you + " Recipients of \"" + environment + "\": " + orNone(allowed) + "." + stale,
		Cause:   err,
	}
}
