package core

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
)

const (
	sshEd25519      = "ssh-ed25519"
	privateKeyBegin = "-----BEGIN OPENSSH PRIVATE KEY-----"
)

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
	key, err := ssh.ParsePublicKey(wire)
	if err != nil || key.Type() != sshEd25519 {
		return nil, "", newError(CodeInvalidKey, "Malformed ssh-ed25519 public key")
	}
	publicKey = key.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
	if err := validateEd25519PublicKey(publicKey); err != nil {
		return nil, "", err
	}
	return publicKey, sshEd25519 + " " + encoded, nil
}

func isOpenSSHPrivateKey(text string) bool {
	return strings.HasPrefix(text, privateKeyBegin)
}

var unknownCipher = regexp.MustCompile(`unknown cipher "([^"]*)"`)

// parseOpenSSHPrivateKey parses an OpenSSH Ed25519 private key, plain or passphrase-protected.
func parseOpenSSHPrivateKey(text string, passphrase func() (string, error)) (ed25519.PrivateKey, error) {
	key, err := ssh.ParseRawPrivateKey([]byte(text))
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == nil {
			return nil, newError(CodeIdentitySource, "The SSH private key is passphrase-protected, but no passphrase is available")
		}
		secret, passphraseErr := passphrase()
		if passphraseErr != nil {
			return nil, passphraseErr
		}
		key, err = ssh.ParseRawPrivateKeyWithPassphrase([]byte(text), []byte(secret))
	}
	if errors.Is(err, x509.IncorrectPasswordError) {
		return nil, wrapError(CodeIdentitySource, err, "Incorrect passphrase for the SSH private key")
	}
	if err != nil {
		if match := unknownCipher.FindStringSubmatch(err.Error()); match != nil {
			return nil, wrapError(CodeIdentitySource, err, "Unsupported OpenSSH private key cipher %s; re-encrypt the key with `ssh-keygen -p -Z aes256-ctr -f KEY`", sanitize(match[1]))
		}
		return nil, wrapError(CodeInvalidKey, err, "Malformed OpenSSH private key: %s", sanitize(err.Error()))
	}

	privateKey, ok := key.(*ed25519.PrivateKey)
	if !ok {
		keyType := "unknown"
		if signer, ok := key.(crypto.Signer); ok {
			if publicKey, err := ssh.NewPublicKey(signer.Public()); err == nil {
				keyType = publicKey.Type()
			}
		}
		return nil, newError(CodeUnsupported, "Only ssh-ed25519 SSH keys are supported (got %s)", keyType)
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(privateKey.Seed()), *privateKey) {
		return nil, newError(CodeInvalidKey, "Inconsistent OpenSSH Ed25519 private key")
	}
	return *privateKey, nil
}
