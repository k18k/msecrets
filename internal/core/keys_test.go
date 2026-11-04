package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"filippo.io/age"
)

var fixtures = filepath.Join("..", "..", "packages", "core", "test", "fixtures")

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtures, name))
	check(t, err)
	return string(data)
}

func roundTrip(t *testing.T, plaintext []byte, recipient age.Recipient, identity age.Identity) []byte {
	t.Helper()
	ciphertext := must[[]byte](t)(EncryptAge(plaintext, []age.Recipient{recipient}))
	return must[[]byte](t)(DecryptAge(ciphertext, []age.Identity{identity}))
}

func TestAgeIdentities(t *testing.T) {
	for _, postQuantum := range []bool{false, true} {
		identity := must[*Identity](t)(GenerateIdentity(postQuantum))
		secret := `^AGE-SECRET-KEY-1[0-9A-Z]+$`
		if postQuantum {
			secret = `^AGE-SECRET-KEY-PQ-1[0-9A-Z]+$`
		}
		if !regexp.MustCompile(secret).MatchString(identity.Secret) || !regexp.MustCompile(`^msecrets1[0-9a-z]+$`).MatchString(identity.PublicKey.Token) {
			t.Fatal(identity.Secret, identity.PublicKey.Token)
		}
		equal(t, identity.PublicKey.PostQuantum, postQuantum)

		parsed := must[*Identity](t)(ParseIdentity(identity.Secret, IdentityOptions{}))
		equal(t, parsed.PublicKey.Token, identity.PublicKey.Token)
		publicKey := must[*PublicKey](t)(ParsePublicKey(identity.PublicKey.Token))
		equal(t, IdentityMatches(identity, publicKey), true)
		equal(t, string(roundTrip(t, []byte("hello"), publicKey.Recipient, parsed.AgeIdentity)), "hello")

		signature := parsed.Sign([]byte("message"))
		equal(t, ed25519.Verify(publicKey.SigningKey, []byte("message"), signature), true)
		equal(t, ed25519.Verify(publicKey.SigningKey, []byte("other"), signature), false)
	}
}

func TestPostQuantumDerivation(t *testing.T) {
	identity := must[*Identity](t)(ParseIdentity("AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR", IdentityOptions{}))
	equal(t, readOnlyToken(t, identity), strings.TrimSpace(fixture(t, "pq-recipient.txt")))
}

func TestReadOnlyRecipients(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	readOnly := must[*PublicKey](t)(ParsePublicKey(readOnlyToken(t, identity)))
	equal(t, readOnly.SigningKey == nil, true)
	equal(t, readOnly.Kind, KindX25519)
	equal(t, IdentityMatches(identity, readOnly), true)
	equal(t, string(roundTrip(t, []byte("x"), readOnly.Recipient, identity.AgeIdentity)), "x")
}

func TestAgeKeygenIdentity(t *testing.T) {
	identity := must[*Identity](t)(ParseIdentity("AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX", IdentityOptions{}))
	equal(t, readOnlyToken(t, identity), "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj")
}

func TestMalformedKeys(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	for _, bad := range []string{"", "hello", "AGE-SECRET-KEY-1abc", identity.Secret[:len(identity.Secret)-1], strings.ToUpper(identity.PublicKey.Token)[:len(identity.PublicKey.Token)-2]} {
		_, err := ParseIdentity(bad, IdentityOptions{})
		expectError(t, err, CodeInvalidKey, "")
	}
	token := identity.PublicKey.Token
	last := "q"
	if strings.HasSuffix(token, "q") {
		last = "p"
	}
	for _, bad := range []string{"", "age1", "msecrets1qqqq", token[:len(token)-1] + last, "ssh-ed25519", "ssh-ed25519 AAAA"} {
		_, err := ParsePublicKey(bad)
		expectError(t, err, "", "")
	}
}

func TestCanonicalTokens(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	equal(t, must[*PublicKey](t)(ParsePublicKey(identity.PublicKey.Token)).Token, identity.PublicKey.Token)
	equal(t, must[*PublicKey](t)(ParsePublicKey(" "+identity.PublicKey.Token+"\n")).Token, identity.PublicKey.Token)
}

func sshFixture(t *testing.T, name string) string { return fixture(t, filepath.Join("ssh", name)) }

func TestSSHKeys(t *testing.T) {
	identity := must[*Identity](t)(ParseIdentity(sshFixture(t, "plain"), IdentityOptions{}))
	publicKey := must[*PublicKey](t)(ParsePublicKey(sshFixture(t, "plain.pub")))
	equal(t, identity.Kind, KindSSHEd25519)
	equal(t, identity.PublicKey.Token, publicKey.Token)
	equal(t, strings.Contains(publicKey.Token, "plain@test"), false)
	equal(t, IdentityMatches(identity, publicKey), true)
	equal(t, string(roundTrip(t, []byte("ssh"), publicKey.Recipient, identity.AgeIdentity)), "ssh")
	equal(t, ed25519.Verify(publicKey.SigningKey, []byte("m"), identity.Sign([]byte("m"))), true)
}

func TestEncryptedSSHKeys(t *testing.T) {
	passphrase := func(text string) IdentityOptions {
		return IdentityOptions{Passphrase: func() (string, error) { return text, nil }}
	}
	for _, name := range []string{"encrypted-ctr", "encrypted-gcm"} {
		_, err := ParseIdentity(sshFixture(t, name), IdentityOptions{})
		expectError(t, err, CodeIdentitySource, "passphrase-protected")
		_, err = ParseIdentity(sshFixture(t, name), passphrase("wrong"))
		expectError(t, err, CodeIdentitySource, "Incorrect passphrase")
		identity := must[*Identity](t)(ParseIdentity(sshFixture(t, name), passphrase("correct horse")))
		equal(t, identity.PublicKey.Token, must[*PublicKey](t)(ParsePublicKey(sshFixture(t, name+".pub"))).Token)
	}
}

func TestRSAKeysUnsupported(t *testing.T) {
	_, err := ParsePublicKey(sshFixture(t, "rsa.pub"))
	expectError(t, err, CodeUnsupported, "")
	_, err = ParseIdentity(sshFixture(t, "rsa"), IdentityOptions{})
	expectError(t, err, CodeUnsupported, "")
}

func TestEd25519NotOnCurve(t *testing.T) {
	wire := wireString([]byte("ssh-ed25519"), bytes.Repeat([]byte{0xff}, 32))
	_, err := ParsePublicKey("ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire))
	expectError(t, err, CodeInvalidKey, "Invalid Ed25519 public key")
}

func TestIdentityFiles(t *testing.T) {
	first := must[*Identity](t)(GenerateIdentity(false))
	second := must[*Identity](t)(GenerateIdentity(false))
	text := FormatIdentityFile(first, "laptop") + "\r\n\r\n# another\r\n" + second.Secret + "\r\n"
	identities := must[[]*Identity](t)(ParseIdentities([]byte(text), IdentityOptions{}))
	equal(t, len(identities), 2)
	equal(t, identities[0].PublicKey.Token, first.PublicKey.Token)
	equal(t, identities[1].PublicKey.Token, second.PublicKey.Token)

	_, err := ParseIdentities([]byte("# nothing here\n"), IdentityOptions{})
	expectError(t, err, CodeInvalidKey, "No identities found")
}

func TestPassphraseEncryptedIdentityFiles(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	recipient := must[age.Recipient](t)(ScryptRecipient("hunter2", 10))
	encrypted := must[[]byte](t)(EncryptAge([]byte(FormatIdentityFile(identity, "")), []age.Recipient{recipient}))
	passphrase := func(text string) IdentityOptions {
		return IdentityOptions{Passphrase: func() (string, error) { return text, nil }}
	}
	for _, contents := range [][]byte{encrypted, []byte(Armor(encrypted))} {
		_, err := ParseIdentities(contents, IdentityOptions{})
		expectError(t, err, CodeIdentitySource, "passphrase-encrypted")
		_, err = ParseIdentities(contents, passphrase("wrong"))
		expectError(t, err, CodeAgeNoMatch, "")
		equal(t, must[[]*Identity](t)(ParseIdentities(contents, passphrase("hunter2")))[0].PublicKey.Token, identity.PublicKey.Token)
	}
}

func TestBech32(t *testing.T) {
	for _, valid := range []string{
		"A12UEL5L", "a12uel5l",
		"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
		"11" + strings.Repeat("q", 82) + "c8247j",
		"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
	} {
		hrp, _, err := bech32Decode(valid)
		check(t, err)
		equal(t, hrp, strings.ToLower(valid[:strings.LastIndex(valid, "1")]))
	}
	for _, invalid := range []string{"pzry9x0s0muk", "1pzry9x0s0muk", "x1b4n0q5v", "li1dgmt3", "A1G7SGD8", "10a06t8", "1qzzfhee", "A12uEL5L"} {
		_, _, err := bech32Decode(invalid)
		expectError(t, err, CodeInvalidKey, "")
	}
	for _, length := range []int{0, 1, 31, 32, 33, 1216} {
		data := bytes.Repeat([]byte{byte(length % 251)}, length)
		encoded := bech32Encode("age", data)
		for _, text := range []string{encoded, strings.ToUpper(encoded)} {
			_, decoded, err := bech32Decode(text)
			check(t, err)
			equal(t, bytes.Equal(decoded, data), true)
		}
	}
	encoded := bech32Encode("age", bytes.Repeat([]byte{7}, 32))
	last := "q"
	if strings.HasSuffix(encoded, "q") {
		last = "p"
	}
	_, _, err := bech32Decode(encoded[:len(encoded)-1] + last)
	expectError(t, err, CodeInvalidKey, "checksum")
}
