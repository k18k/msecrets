package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"regexp"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blowfish"
)

const (
	sshEd25519       = "ssh-ed25519"
	privateKeyBegin  = "-----BEGIN OPENSSH PRIVATE KEY-----"
	privateKeyEnd    = "-----END OPENSSH PRIVATE KEY-----"
	privateKeyMagic  = "openssh-key-v1\x00"
	incorrectSSHPass = "Incorrect passphrase for the SSH private key"
)

func wireString(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = binary.BigEndian.AppendUint32(out, uint32(len(part)))
		out = append(out, part...)
	}
	return out
}

type wireReader struct {
	data []byte
	what string
	err  error
}

func (r *wireReader) uint32() uint32 {
	if r.err != nil || len(r.data) < 4 {
		r.err = newError(CodeInvalidKey, "Malformed %s", r.what)
		return 0
	}
	value := binary.BigEndian.Uint32(r.data)
	r.data = r.data[4:]
	return value
}

func (r *wireReader) string() []byte {
	length := r.uint32()
	if r.err != nil || uint32(len(r.data)) < length {
		r.err = newError(CodeInvalidKey, "Malformed %s", r.what)
		return nil
	}
	value := r.data[:length]
	r.data = r.data[length:]
	return value
}

// validateEd25519PublicKey rejects encodings that are not canonical points with a nonzero Montgomery u-coordinate.
func validateEd25519PublicKey(publicKey []byte) error {
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil || !bytes.Equal(point.Bytes(), publicKey) || bytes.Equal(point.BytesMontgomery(), make([]byte, 32)) {
		return newError(CodeInvalidKey, "Invalid Ed25519 public key")
	}
	return nil
}

var whitespace = regexp.MustCompile(`\s+`)

// parseSSHPublicKey parses an "ssh-ed25519 AAAA… [comment]" line into the raw key and the canonical token.
func parseSSHPublicKey(line string) (publicKey []byte, token string, err error) {
	fields := whitespace.Split(jsTrim(line), -1)
	keyType := fields[0]
	if keyType != sshEd25519 || len(fields) < 2 || fields[1] == "" {
		code := CodeInvalidKey
		if strings.HasPrefix(keyType, "ssh-") || strings.HasPrefix(keyType, "ecdsa-") {
			code = CodeUnsupported
		}
		got := ""
		if keyType != "" {
			got = " (got " + sanitize(keyType) + ")"
		}
		return nil, "", newError(code, "Only ssh-ed25519 SSH keys are supported%s", got)
	}
	encoded := fields[1]
	wire, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(wire) != encoded {
		return nil, "", newError(CodeInvalidKey, "Malformed ssh-ed25519 public key encoding")
	}
	reader := &wireReader{data: wire, what: "ssh-ed25519 public key"}
	wireType := reader.string()
	publicKey = bytes.Clone(reader.string())
	if reader.err != nil {
		return nil, "", reader.err
	}
	if string(wireType) != sshEd25519 || len(publicKey) != 32 || len(reader.data) != 0 {
		return nil, "", newError(CodeInvalidKey, "Malformed ssh-ed25519 public key")
	}
	if err := validateEd25519PublicKey(publicKey); err != nil {
		return nil, "", err
	}
	return publicKey, sshEd25519 + " " + encoded, nil
}

func isOpenSSHPrivateKey(text string) bool {
	return strings.HasPrefix(text, privateKeyBegin)
}

type sshCipher struct{ keyLength, ivLength, tagLength int }

var sshCiphers = map[string]sshCipher{
	"none":                   {},
	"aes256-ctr":             {32, 16, 0},
	"aes256-cbc":             {32, 16, 0},
	"aes256-gcm@openssh.com": {32, 12, 16},
}

func decryptPrivateSection(cipherName, kdfName string, kdfOptions, encrypted, tag []byte, passphrase func() (string, error)) ([]byte, error) {
	spec, ok := sshCiphers[cipherName]
	if !ok {
		return nil, newError(CodeUnsupported, "Unsupported OpenSSH private key cipher %s", sanitize(cipherName))
	}
	if cipherName == "none" {
		return encrypted, nil
	}
	if kdfName != "bcrypt" {
		return nil, newError(CodeUnsupported, "Unsupported OpenSSH private key KDF %s", sanitize(kdfName))
	}
	if passphrase == nil {
		return nil, newError(CodeIdentitySource, "The SSH private key is passphrase-protected, but no passphrase is available")
	}
	options := &wireReader{data: kdfOptions, what: "OpenSSH KDF options"}
	salt := options.string()
	rounds := options.uint32()
	if options.err != nil {
		return nil, options.err
	}
	secret, err := passphrase()
	if err != nil {
		return nil, err
	}
	derived := bcryptPBKDF([]byte(secret), salt, int(rounds), spec.keyLength+spec.ivLength)
	defer clear(derived)
	block, _ := aes.NewCipher(derived[:spec.keyLength])
	iv := derived[spec.keyLength:]
	plain := make([]byte, len(encrypted))
	switch cipherName {
	case "aes256-ctr":
		cipher.NewCTR(block, iv).XORKeyStream(plain, encrypted)
	case "aes256-cbc":
		if len(encrypted)%aes.BlockSize != 0 {
			return nil, newError(CodeIdentitySource, incorrectSSHPass)
		}
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, encrypted)
	default:
		gcm, _ := cipher.NewGCM(block)
		if len(tag) != spec.tagLength {
			return nil, newError(CodeInvalidKey, "Malformed OpenSSH private key")
		}
		if plain, err = gcm.Open(nil, iv, append(bytes.Clone(encrypted), tag...), nil); err != nil {
			return nil, wrapError(CodeIdentitySource, err, incorrectSSHPass)
		}
	}
	return plain, nil
}

type openSSHPrivateKey struct {
	seed          []byte
	publicKey     []byte
	publicKeyLine string
}

func parseOpenSSHPrivateKey(text string, passphrase func() (string, error)) (*openSSHPrivateKey, error) {
	malformed := newError(CodeInvalidKey, "Malformed OpenSSH private key")
	lines := lineBreak.Split(jsTrim(text), -1)
	if lines[0] != privateKeyBegin || lines[len(lines)-1] != privateKeyEnd || len(lines) < 2 {
		return nil, malformed
	}
	data, err := base64.StdEncoding.DecodeString(strings.Join(lines[1:len(lines)-1], ""))
	if err != nil || !bytes.HasPrefix(data, []byte(privateKeyMagic)) {
		return nil, malformed
	}

	reader := &wireReader{data: data[len(privateKeyMagic):], what: "OpenSSH private key"}
	cipherName := string(reader.string())
	kdfName := string(reader.string())
	kdfOptions := reader.string()
	count := reader.uint32()
	if reader.err != nil {
		return nil, reader.err
	}
	if count != 1 {
		return nil, newError(CodeUnsupported, "OpenSSH private key files with multiple keys are not supported")
	}
	publicWire := reader.string()
	encrypted := reader.string()
	if reader.err != nil {
		return nil, reader.err
	}
	plain, err := decryptPrivateSection(cipherName, kdfName, kdfOptions, encrypted, reader.data, passphrase)
	if err != nil {
		return nil, err
	}
	defer clear(plain)

	section := &wireReader{data: plain, what: "OpenSSH private key"}
	if section.uint32() != section.uint32() || section.err != nil {
		if section.err != nil {
			return nil, section.err
		}
		return nil, newError(CodeIdentitySource, incorrectSSHPass)
	}
	keyType := string(section.string())
	if section.err == nil && keyType != sshEd25519 {
		return nil, newError(CodeUnsupported, "Only ssh-ed25519 SSH keys are supported (got %s)", sanitize(keyType))
	}
	publicKey := bytes.Clone(section.string())
	privateKey := section.string()
	section.string() // comment
	if section.err != nil {
		return nil, section.err
	}
	if len(publicKey) != 32 || len(privateKey) != 64 || !bytes.Equal(privateKey[32:], publicKey) ||
		!bytes.Equal(publicWire, wireString([]byte(sshEd25519), publicKey)) {
		return nil, newError(CodeInvalidKey, "Inconsistent OpenSSH Ed25519 private key")
	}
	return &openSSHPrivateKey{
		seed:          bytes.Clone(privateKey[:32]),
		publicKey:     publicKey,
		publicKeyLine: sshEd25519 + " " + base64.StdEncoding.EncodeToString(publicWire),
	}, nil
}

// bcryptPBKDF derives a key as OpenSSH does for encrypted private keys.
func bcryptPBKDF(password, salt []byte, rounds, keyLength int) []byte {
	const blockSize = 32
	blocks := (keyLength + blockSize - 1) / blockSize
	key := make([]byte, blocks*blockSize)
	passwordHash := sha512.Sum512(password)
	for block := 1; block <= blocks; block++ {
		saltHash := sha512.Sum512(binary.BigEndian.AppendUint32(bytes.Clone(salt), uint32(block)))
		hashed := bcryptHash(passwordHash[:], saltHash[:])
		out := bytes.Clone(hashed)
		for round := 1; round < rounds; round++ {
			saltHash = sha512.Sum512(hashed)
			hashed = bcryptHash(passwordHash[:], saltHash[:])
			for i := range out {
				out[i] ^= hashed[i]
			}
		}
		for i, value := range out {
			key[i*blocks+block-1] = value
		}
	}
	return key[:keyLength]
}

func bcryptHash(passwordHash, saltHash []byte) []byte {
	c, _ := blowfish.NewSaltedCipher(passwordHash, saltHash)
	for range 64 {
		blowfish.ExpandKey(saltHash, c)
		blowfish.ExpandKey(passwordHash, c)
	}
	out := []byte("OxychromaticBlowfishSwatDynamite")
	for i := 0; i < len(out); i += 8 {
		for range 64 {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	for i := 0; i < len(out); i += 4 {
		out[i], out[i+1], out[i+2], out[i+3] = out[i+3], out[i+2], out[i+1], out[i]
	}
	return out
}
