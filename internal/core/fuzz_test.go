package core

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// FuzzParseDocumentText: parsing never panics, and whatever validates serializes stably.
func FuzzParseDocumentText(f *testing.F) {
	document, _ := sampleDocument(f)
	f.Add(SerializeDocument(document))
	f.Add(`{"version":4,"id":"00000000000000000000000000000000","recipients":{},"environments":{"0":{"recipients":[]}},"secrets":{}}`)
	f.Add(`{"a":[1e400,-0,"🔐",null,true]}`)
	f.Fuzz(func(t *testing.T, text string) {
		parsed, err := ParseDocumentText(text, "")
		if err != nil {
			if !IsError(err, CodeInvalidFile) {
				t.Fatalf("unexpected %#v", err)
			}
			return
		}
		serialized := SerializeDocument(parsed)
		again := must[*Document](t)(ParseDocumentText(serialized, ""))
		equal(t, SerializeDocument(again), serialized)
		must[Report](t)(Inspect(parsed))
	})
}

const fuzzIdentity = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"

// FuzzDecryptAge: decryption never panics, fails only with *Error, and never
// accepts a file that the reference age CLI rejects (when it is installed).
func FuzzDecryptAge(f *testing.F) {
	identity := must[*Identity](f)(ParseIdentity(fuzzIdentity, IdentityOptions{}))
	for _, plaintext := range []string{"", "secret", string(bytes.Repeat([]byte("x"), 70_000))} {
		file := must[[]byte](f)(EncryptAge([]byte(plaintext), []age.Recipient{identity.PublicKey.Recipient}))
		f.Add(file)
		f.Add([]byte(Armor(file)))
	}
	ageBinary, _ := exec.LookPath("age")
	keyFile := filepath.Join(f.TempDir(), "key.txt")
	writeFile(f, keyFile, fuzzIdentity+"\n")

	f.Fuzz(func(t *testing.T, file []byte) {
		plaintext, err := DecryptAge(file, []age.Identity{identity.AgeIdentity})
		if err != nil {
			if !IsError(err) {
				t.Fatalf("unexpected %#v", err)
			}
			return
		}
		if ageBinary == "" {
			return
		}
		cmd := exec.Command(ageBinary, "-d", "-i", keyFile)
		cmd.Stdin = bytes.NewReader(file)
		reference, err := cmd.Output()
		if err != nil {
			t.Fatalf("accepted a file that age rejects: %v", err)
		}
		if !bytes.Equal(reference, plaintext) {
			t.Fatal("plaintext differs from age")
		}
	})
}
