package core

// msecrets keys.
//
// Identities are standard age identities (AGE-SECRET-KEY-1…, AGE-SECRET-KEY-PQ-1…)
// or OpenSSH Ed25519 keys. Every identity can also sign: for age identities an
// Ed25519 signing key is derived from the secret with HKDF.
//
// Public keys come in these forms:
//   - msecrets1…: encryption key and Ed25519 signing key in one token (read + write)
//   - age1… / age1pq1…: plain age recipients (read-only, cannot sign values)
//   - ssh-ed25519 AAAA…: OpenSSH Ed25519 public keys (read + write)

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ssh"
)

// KeyKind is the kind of a key.
type KeyKind string

// Key kinds.
const (
	KindX25519         KeyKind = "x25519"
	KindMLKEM768X25519 KeyKind = "mlkem768x25519"
	KindSSHEd25519     KeyKind = "ssh-ed25519"
)

// PublicKey is a parsed recipient public key.
type PublicKey struct {
	Kind KeyKind
	// Token is the canonical string form, as stored in the secrets file.
	Token string
	// EncryptionKey is the raw encryption key; equal for every token form of the same key.
	EncryptionKey []byte
	// SigningKey is the Ed25519 verification key, or nil for encrypt-only (read-only) recipients.
	SigningKey  ed25519.PublicKey
	PostQuantum bool
	Recipient   age.Recipient
}

// id identifies the key independently of its token form.
func (key *PublicKey) id() string {
	return string(key.Kind) + ":" + hex.EncodeToString(key.EncryptionKey)
}

// Identity is a private key.
type Identity struct {
	Kind KeyKind
	// PublicKey is the full public key of this identity, including its signing key.
	PublicKey   *PublicKey
	AgeIdentity age.Identity
	// Secret is the identity in its portable string form. Handle with care.
	Secret     string
	signingKey ed25519.PrivateKey
}

// Sign signs message with the identity's Ed25519 signing key.
func (identity *Identity) Sign(message []byte) []byte {
	return ed25519.Sign(identity.signingKey, message)
}

const (
	msecretsHRP        = "msecrets"
	x25519IdentityHRP  = "age-secret-key-"
	hybridIdentityHRP  = "age-secret-key-pq-"
	x25519RecipientHRP = "age"
	hybridRecipientHRP = "age1pq"
	signingKeyInfo     = "msecrets/v4/ed25519-signing-key"
	hybridKeySize      = 1184 + 32
)

var kindTags = map[KeyKind]byte{KindX25519: 0x01, KindMLKEM768X25519: 0x02}

var lineBreak = regexp.MustCompile(`\r?\n`)

func agePublicKey(kind KeyKind, encryptionKey, signingKey []byte) (*PublicKey, error) {
	var token string
	if signingKey != nil {
		token = bech32Encode(msecretsHRP, append(append([]byte{kindTags[kind]}, signingKey...), encryptionKey...))
	} else if kind == KindX25519 {
		token = bech32Encode(x25519RecipientHRP, encryptionKey)
	} else {
		token = bech32Encode(hybridRecipientHRP, encryptionKey)
	}

	var recipient age.Recipient
	var err error
	if kind == KindX25519 {
		recipient, err = age.ParseX25519Recipient(bech32Encode(x25519RecipientHRP, encryptionKey))
	} else {
		recipient, err = age.ParseHybridRecipient(bech32Encode(hybridRecipientHRP, encryptionKey))
	}
	if err != nil {
		return nil, wrapError(CodeInvalidKey, err, "Invalid %s public key", kind)
	}
	return &PublicKey{
		Kind:          kind,
		Token:         token,
		EncryptionKey: bytes.Clone(encryptionKey),
		SigningKey:    bytes.Clone(signingKey),
		PostQuantum:   kind == KindMLKEM768X25519,
		Recipient:     recipient,
	}, nil
}

func ageIdentity(kind KeyKind, secretKey []byte) (*Identity, error) {
	seed, err := hkdf.Key(sha256.New, secretKey, nil, signingKeyInfo, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	signingKey := ed25519.NewKeyFromSeed(seed)

	var ageID age.Identity
	var encryptionKey []byte
	if kind == KindX25519 {
		secret := strings.ToUpper(bech32Encode(x25519IdentityHRP, secretKey))
		identity, err := age.ParseX25519Identity(secret)
		if err != nil {
			return nil, wrapError(CodeInvalidKey, err, "Malformed age identity")
		}
		ageID = identity
		encryptionKey, err = curve25519.X25519(secretKey, curve25519.Basepoint)
		if err != nil {
			return nil, wrapError(CodeInvalidKey, err, "Malformed age identity")
		}
	} else {
		identity, err := age.ParseHybridIdentity(strings.ToUpper(bech32Encode(hybridIdentityHRP, secretKey)))
		if err != nil {
			return nil, wrapError(CodeInvalidKey, err, "Malformed age identity")
		}
		ageID = identity
		if _, encryptionKey, err = bech32Decode(identity.Recipient().String()); err != nil {
			return nil, err
		}
	}

	publicKey, err := agePublicKey(kind, encryptionKey, signingKey.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	hrp := x25519IdentityHRP
	if kind == KindMLKEM768X25519 {
		hrp = hybridIdentityHRP
	}
	return &Identity{
		Kind:        kind,
		PublicKey:   publicKey,
		AgeIdentity: ageID,
		Secret:      strings.ToUpper(bech32Encode(hrp, secretKey)),
		signingKey:  signingKey,
	}, nil
}

// GenerateIdentity creates a new random age identity (post-quantum hybrid if requested).
func GenerateIdentity(postQuantum bool) (*Identity, error) {
	kind := KindX25519
	if postQuantum {
		kind = KindMLKEM768X25519
	}
	return ageIdentity(kind, randomBytes(32))
}

// IdentityOptions configures identity parsing.
type IdentityOptions struct {
	// Passphrase returns the passphrase for a passphrase-encrypted identity file or SSH key.
	Passphrase func() (string, error)
}

var ageSecretKeyPrefix = regexp.MustCompile(`(?i)^AGE-SECRET-KEY-`)

// ParseIdentity parses a single identity: an age secret key string or an OpenSSH private key.
func ParseIdentity(text string, options IdentityOptions) (*Identity, error) {
	trimmed := jsTrim(text)

	if isOpenSSHPrivateKey(trimmed) {
		privateKey, err := parseOpenSSHPrivateKey(trimmed, options.Passphrase)
		if err != nil {
			return nil, err
		}
		sshKey, err := ssh.NewPublicKey(privateKey.Public())
		if err != nil {
			return nil, wrapError(CodeInvalidKey, err, "Invalid Ed25519 public key")
		}
		publicKey, err := sshPublicKey(sshEd25519 + " " + base64.StdEncoding.EncodeToString(sshKey.Marshal()))
		if err != nil {
			return nil, err
		}
		ageID, err := agessh.NewEd25519Identity(privateKey)
		if err != nil {
			return nil, wrapError(CodeInvalidKey, err, "Invalid Ed25519 public key")
		}
		return &Identity{
			Kind:        KindSSHEd25519,
			PublicKey:   publicKey,
			AgeIdentity: ageID,
			Secret:      trimmed,
			signingKey:  privateKey,
		}, nil
	}

	if !ageSecretKeyPrefix.MatchString(trimmed) {
		return nil, newError(CodeInvalidKey, "Unrecognized identity: expected an AGE-SECRET-KEY-1…, AGE-SECRET-KEY-PQ-1…, or OpenSSH Ed25519 private key")
	}
	hrp, secretKey, err := bech32Decode(trimmed)
	if err != nil {
		return nil, err
	}
	if (hrp != x25519IdentityHRP && hrp != hybridIdentityHRP) || len(secretKey) != 32 {
		return nil, newError(CodeInvalidKey, "Malformed age identity")
	}
	if hrp == x25519IdentityHRP {
		return ageIdentity(KindX25519, secretKey)
	}
	return ageIdentity(KindMLKEM768X25519, secretKey)
}

// ParseIdentities parses identity file contents: one identity per line with
// '#' comments (age format), an OpenSSH private key, or a passphrase-encrypted
// age file (binary or armored) containing either of those.
func ParseIdentities(contents []byte, options IdentityOptions) ([]*Identity, error) {
	text := string(contents)

	if strings.HasPrefix(text, "age-encryption.org/") || strings.HasPrefix(strings.TrimLeftFunc(text, isJSSpace), armorBegin) {
		if options.Passphrase == nil {
			return nil, newError(CodeIdentitySource, "The identity file is passphrase-encrypted, but no passphrase is available")
		}
		passphrase, err := options.Passphrase()
		if err != nil {
			return nil, err
		}
		identity, err := ScryptIdentity(passphrase)
		if err != nil {
			return nil, err
		}
		decrypted, err := DecryptAge(contents, []age.Identity{identity})
		if err != nil {
			return nil, err
		}
		defer clear(decrypted)
		return ParseIdentities(decrypted, IdentityOptions{})
	}

	if isOpenSSHPrivateKey(jsTrim(text)) {
		identity, err := ParseIdentity(text, options)
		if err != nil {
			return nil, err
		}
		return []*Identity{identity}, nil
	}

	var identities []*Identity
	for _, line := range lineBreak.Split(text, -1) {
		line = jsTrim(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		identity, err := ParseIdentity(line, IdentityOptions{})
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	if len(identities) == 0 {
		return nil, newError(CodeInvalidKey, "No identities found")
	}
	return identities, nil
}

func sshPublicKey(line string) (*PublicKey, error) {
	publicKey, token, err := parseSSHPublicKey(line)
	if err != nil {
		return nil, err
	}
	sshKey, err := ssh.NewPublicKey(ed25519.PublicKey(publicKey))
	if err != nil {
		return nil, wrapError(CodeInvalidKey, err, "Invalid Ed25519 public key")
	}
	recipient, err := agessh.NewEd25519Recipient(sshKey)
	if err != nil {
		return nil, wrapError(CodeInvalidKey, err, "Invalid Ed25519 public key")
	}
	return &PublicKey{
		Kind:          KindSSHEd25519,
		Token:         token,
		EncryptionKey: publicKey,
		SigningKey:    publicKey,
		Recipient:     recipient,
	}, nil
}

// ParsePublicKey parses a recipient public key in any supported form.
func ParsePublicKey(text string) (*PublicKey, error) {
	trimmed := jsTrim(text)
	if strings.HasPrefix(trimmed, "ssh-") {
		return sshPublicKey(trimmed)
	}

	hrp, data, err := bech32Decode(trimmed)
	if err != nil {
		return nil, err
	}
	switch {
	case hrp == msecretsHRP:
		var kind KeyKind
		for candidate, tag := range kindTags {
			if len(data) > 0 && data[0] == tag {
				kind = candidate
			}
		}
		size := 32
		if kind == KindMLKEM768X25519 {
			size = hybridKeySize
		}
		if kind == "" || len(data) != 33+size {
			return nil, newError(CodeInvalidKey, "Malformed msecrets public key")
		}
		return agePublicKey(kind, data[33:], data[1:33])
	case hrp == x25519RecipientHRP && len(data) == 32:
		return agePublicKey(KindX25519, data, nil)
	case hrp == hybridRecipientHRP && len(data) == hybridKeySize:
		return agePublicKey(KindMLKEM768X25519, data, nil)
	}
	return nil, newError(CodeInvalidKey, "Unrecognized public key: expected msecrets1…, age1…, age1pq1…, or ssh-ed25519 AAAA…")
}

// ReadOnlyPublicKey returns the encrypt-only form of a public key (age1… / age1pq1…):
// its holder can read but never write values.
func ReadOnlyPublicKey(publicKey *PublicKey) (*PublicKey, error) {
	if publicKey.Kind == KindSSHEd25519 {
		return nil, newError(CodeUsage, "SSH keys always include their signing key; use an age key for read-only access")
	}
	return agePublicKey(publicKey.Kind, publicKey.EncryptionKey, nil)
}

// IdentityMatches reports whether an identity holds the private key for a recipient public key.
func IdentityMatches(identity *Identity, publicKey *PublicKey) bool {
	return identity.Kind == publicKey.Kind && bytes.Equal(identity.PublicKey.EncryptionKey, publicKey.EncryptionKey)
}

// FormatIdentityFile renders an identity file in the age format.
func FormatIdentityFile(identity *Identity, comment string) string {
	if identity.Kind == KindSSHEd25519 {
		return identity.Secret + "\n"
	}
	lines := []string{"# msecrets identity: keep this secret, never commit it"}
	if comment != "" {
		lines = append(lines, "# "+comment)
	}
	lines = append(lines, "# public key: "+identity.PublicKey.Token, identity.Secret, "")
	return strings.Join(lines, "\n")
}
