package core

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

var vectorCodes = map[string]ErrorCode{
	"header failure":  CodeAgeHeader,
	"no match":        CodeAgeNoMatch,
	"HMAC failure":    CodeAgeHMAC,
	"payload failure": CodeAgePayload,
	"armor failure":   CodeAgeArmor,
}

// TestAgeVectors runs the C2SP age test vectors through DecryptAge.
func TestAgeVectors(t *testing.T) {
	directory := filepath.Join(fixtures, "..", "vectors")
	entries, err := os.ReadDir(directory)
	check(t, err)
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(directory, entry.Name()))
			check(t, err)
			head, body, _ := bytes.Cut(raw, []byte("\n\n"))
			fields := map[string][]string{}
			for _, line := range strings.Split(string(head), "\n") {
				key, value, _ := strings.Cut(line, ": ")
				fields[key] = append(fields[key], value)
			}
			if len(fields["compressed"]) > 0 && fields["compressed"][0] == "zlib" {
				reader, err := zlib.NewReader(bytes.NewReader(body))
				check(t, err)
				body, err = io.ReadAll(reader)
				check(t, err)
			}
			var identities []age.Identity
			for _, text := range fields["identity"] {
				identities = append(identities, must[[]age.Identity](t)(age.ParseIdentities(strings.NewReader(text)))...)
			}
			for _, passphrase := range fields["passphrase"] {
				identities = append(identities, must[age.Identity](t)(ScryptIdentity(passphrase)))
			}

			plaintext, err := DecryptAge(body, identities)
			if expect := fields["expect"][0]; expect == "success" {
				check(t, err)
				digest := sha256.Sum256(plaintext)
				equal(t, hex.EncodeToString(digest[:]), fields["payload"][0])
			} else {
				code, ok := vectorCodes[expect]
				if !ok {
					t.Fatalf("unknown expectation %s", expect)
				}
				expectError(t, err, code, "")
			}
		})
	}
}

func TestArmorRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, 47, 48, 49, 200} {
		data := bytes.Repeat([]byte{7}, size)
		equal(t, bytes.Equal(must[[]byte](t)(Dearmor(Armor(data))), data), true)
	}
}

// unknownRecipient wraps the file key into a stanza no identity recognizes.
type unknownRecipient struct{ body []byte }

func (r unknownRecipient) Wrap([]byte) ([]*age.Stanza, error) {
	return []*age.Stanza{{Type: "unknown-type", Args: []string{"argument"}, Body: r.body}}, nil
}

func testRecipients(t *testing.T) (*Identity, *Identity, []age.Recipient) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	sshIdentity := must[*Identity](t)(ParseIdentity(sshFixture(t, "plain"), IdentityOptions{}))
	return identity, sshIdentity, []age.Recipient{
		identity.PublicKey.Recipient,
		must[*Identity](t)(GenerateIdentity(true)).PublicKey.Recipient,
		sshIdentity.PublicKey.Recipient,
	}
}

func TestChunkBoundaries(t *testing.T) {
	identity, sshIdentity, recipients := testRecipients(t)
	random := rand.New(rand.NewPCG(1, 2))
	for _, size := range []int{0, 1, 64*1024 - 1, 64 * 1024, 64*1024 + 1, 3 * 64 * 1024} {
		plaintext := make([]byte, size)
		for i := range plaintext {
			plaintext[i] = byte(random.IntN(256))
		}
		for _, id := range []*Identity{identity, sshIdentity} {
			ciphertext := must[[]byte](t)(EncryptAge(plaintext, recipients))
			equal(t, bytes.Equal(must[[]byte](t)(DecryptAge(ciphertext, []age.Identity{id.AgeIdentity})), plaintext), true)
		}
	}
}

// attempt fails the test unless err is nil or an *Error (never another error).
func attempt(t *testing.T, err error) error {
	t.Helper()
	if err != nil && !IsError(err) {
		t.Fatalf("unexpected %#v", err)
	}
	return err
}

func TestBitFlipsAndTruncations(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	ids := []age.Identity{identity.AgeIdentity}
	file := must[[]byte](t)(EncryptAge([]byte("secret"), []age.Recipient{unknownRecipient{bytes.Repeat([]byte{1}, 48)}, identity.PublicKey.Recipient}))
	for bit := 0; bit < len(file)*8; bit++ {
		flipped := bytes.Clone(file)
		flipped[bit>>3] ^= 1 << (bit & 7)
		if _, err := DecryptAge(flipped, ids); attempt(t, err) == nil {
			t.Fatalf("bit %d", bit)
		}
	}
	for length := range len(file) {
		if _, err := DecryptAge(file[:length], ids); attempt(t, err) == nil {
			t.Fatalf("length %d", length)
		}
	}
}

func fuzzCases() int {
	if n := os.Getenv("MSECRETS_FUZZ_CASES"); n != "" {
		var cases int
		for _, digit := range n {
			cases = cases*10 + int(digit-'0')
		}
		return cases
	}
	return 300
}

// mutate applies a random mutation that keeps most of an age file intact.
func mutate(file []byte, random *rand.Rand) []byte {
	file = bytes.Clone(file)
	switch random.IntN(6) {
	case 0:
		if len(file) > 0 {
			file[random.IntN(len(file))] ^= 1 << random.IntN(8)
		}
	case 1:
		file = file[:random.IntN(len(file)+1)]
	case 2:
		index := random.IntN(len(file) + 1)
		file = append(file[:index:index], append([]byte{byte(random.IntN(256))}, file[index:]...)...)
	case 3:
		if len(file) > 0 {
			index := random.IntN(len(file))
			file = append(file[:index:index], file[index+1:]...)
		}
	case 4:
		file = append(file, byte(random.IntN(256)))
	default:
		mac := bytes.Index(file, []byte("\n--- "))
		if mac < 0 {
			return file
		}
		lines := strings.Split(string(file[:mac]), "\n")
		index := random.IntN(len(lines))
		if random.IntN(2) == 0 {
			lines = append(lines[:index+1], lines[index:]...)
		} else if len(lines) > 1 {
			lines = append(lines[:index], lines[index+1:]...)
		}
		file = append([]byte(strings.Join(lines, "\n")), file[mac:]...)
	}
	return file
}

func TestRandomMutations(t *testing.T) {
	identity, _, recipients := testRecipients(t)
	random := rand.New(rand.NewPCG(20261021, 0))
	for index := range fuzzCases() {
		plaintext := bytes.Repeat([]byte{byte(index)}, []int{0, 5, 70_000}[random.IntN(3)])
		file := must[[]byte](t)(EncryptAge(plaintext, []age.Recipient{recipients[random.IntN(len(recipients))], identity.PublicKey.Recipient}))
		for count := 1 + random.IntN(3); count > 0; count-- {
			file = mutate(file, random)
		}
		result, err := DecryptAge(file, []age.Identity{identity.AgeIdentity})
		if attempt(t, err) == nil && !bytes.Equal(result, plaintext) {
			t.Fatalf("case %d: other plaintext", index)
		}
	}
}

func TestRandomBytes(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	random := rand.New(rand.NewPCG(20261021, 1))
	for range fuzzCases() {
		garbage := make([]byte, random.IntN(300))
		for i := range garbage {
			garbage[i] = byte(random.IntN(256))
		}
		if random.IntN(2) == 0 {
			garbage = append([]byte("age-encryption.org/v1\n"), garbage...)
		}
		if _, err := DecryptAge(garbage, []age.Identity{identity.AgeIdentity}); attempt(t, err) == nil {
			t.Fatal("garbage accepted")
		}
	}
}

func TestNotARecipient(t *testing.T) {
	_, _, recipients := testRecipients(t)
	file := must[[]byte](t)(EncryptAge([]byte("secret"), recipients))
	_, err := DecryptAge(file, []age.Identity{must[*Identity](t)(GenerateIdentity(false)).AgeIdentity})
	expectError(t, err, CodeAgeNoMatch, "")
	_, err = DecryptAge(file, nil)
	expectError(t, err, CodeAgeNoMatch, "")
}

func TestHeaderBounds(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	ids := []age.Identity{identity.AgeIdentity}
	stanzas := func(count int) []age.Recipient {
		recipients := make([]age.Recipient, count)
		for i := range recipients {
			recipients[i] = unknownRecipient{}
		}
		return append(recipients, identity.PublicKey.Recipient)
	}
	full := must[[]byte](t)(EncryptAge([]byte("x"), stanzas(MaxStanzas-1)))
	equal(t, string(must[[]byte](t)(DecryptAge(full, ids))), "x")
	_, err := EncryptAge([]byte("x"), stanzas(MaxStanzas))
	expectError(t, err, CodeUsage, "")

	header := func(lines string) []byte {
		return []byte("age-encryption.org/v1\n" + lines + "--- " + strings.Repeat("A", 43) + "\n")
	}
	_, err = DecryptAge(header(strings.Repeat("-> x\n\n", MaxStanzas+1)), ids)
	expectError(t, err, CodeAgeHeader, "more than 1024 recipient stanzas")
	_, err = DecryptAge(header("-> x\n"+strings.Repeat(strings.Repeat("A", 64)+"\n", 17_000)+"\n"), ids)
	expectError(t, err, CodeAgeHeader, "larger than 1 MiB")
}

func TestScryptMustBeAlone(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	scrypt := must[age.Recipient](t)(ScryptRecipient("pw", 10))
	_, err := EncryptAge([]byte("x"), []age.Recipient{scrypt, identity.PublicKey.Recipient})
	expectError(t, err, CodeUsage, "passphrase recipient")
}

func TestMixedPostQuantumAndClassical(t *testing.T) {
	classic, _, recipients := testRecipients(t)
	file := must[[]byte](t)(EncryptAge([]byte("mixed"), recipients))
	equal(t, string(must[[]byte](t)(DecryptAge(file, []age.Identity{classic.AgeIdentity}))), "mixed")
}

func TestLinearTimeArmor(t *testing.T) {
	_, err := Dearmor("x" + strings.Repeat(" \t", 200_000) + "y")
	expectError(t, err, CodeAgeArmor, "")
	plan := must[CommandPlan](t)(PlanCommand(testHost{WithEnv(NativeHost(), map[string]string{}), "windows"}, []string{"tool.cmd", strings.Repeat(`\`, 200_000) + "x"}, "/"))
	equal(t, plan.Verbatim, true)
}

// TestAgeInterop checks both directions against the reference age CLI.
func TestAgeInterop(t *testing.T) {
	ageBinary, err := exec.LookPath("age")
	if err != nil {
		t.Skip("age binary not available")
	}
	run := func(input []byte, args ...string) []byte {
		cmd := exec.Command(ageBinary, args...)
		cmd.Stdin = bytes.NewReader(input)
		output, err := cmd.Output()
		check(t, err)
		return output
	}
	directory := t.TempDir()
	plaintext := []byte(strings.Repeat("interop ✓ ", 10_000))
	for _, postQuantum := range []bool{false, true} {
		identity := must[*Identity](t)(GenerateIdentity(postQuantum))
		keyFile := filepath.Join(directory, "key")
		writeFile(t, keyFile, identity.Secret+"\n")
		ciphertext := must[[]byte](t)(EncryptAge(plaintext, []age.Recipient{identity.PublicKey.Recipient}))
		equal(t, bytes.Equal(run(ciphertext, "-d", "-i", keyFile), plaintext), true)
		equal(t, bytes.Equal(run([]byte(Armor(ciphertext)), "-d", "-i", keyFile), plaintext), true)

		recipient := readOnlyToken(t, identity)
		fromAge := run(plaintext, "-a", "-r", recipient)
		equal(t, bytes.Equal(must[[]byte](t)(DecryptAge(fromAge, []age.Identity{identity.AgeIdentity})), plaintext), true)
	}
	if keygen, err := exec.LookPath("age-keygen"); err == nil {
		output, err := exec.Command(keygen, "-pq").Output()
		check(t, err)
		var secret string
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "AGE-") {
				secret = line
			}
		}
		keyFile := filepath.Join(directory, "pq.key")
		writeFile(t, keyFile, secret+"\n")
		recipient, err := exec.Command(keygen, "-y", keyFile).Output()
		check(t, err)
		identity := must[*Identity](t)(ParseIdentity(secret, IdentityOptions{}))
		equal(t, readOnlyToken(t, identity), strings.TrimSpace(string(recipient)))
	}

	sshIdentity := must[*Identity](t)(ParseIdentity(sshFixture(t, "plain"), IdentityOptions{}))
	plain := filepath.Join(fixtures, "ssh", "plain")
	fromUs := must[[]byte](t)(EncryptAge(plaintext, []age.Recipient{sshIdentity.PublicKey.Recipient}))
	equal(t, bytes.Equal(run(fromUs, "-d", "-i", plain), plaintext), true)
	fromAge := run(plaintext, "-R", plain+".pub")
	equal(t, bytes.Equal(must[[]byte](t)(DecryptAge(fromAge, []age.Identity{sshIdentity.AgeIdentity})), plaintext), true)
}
