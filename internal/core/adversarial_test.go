package core

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
)

func TestKeysWithOneChangedCharacter(t *testing.T) {
	identity := must[*Identity](t)(GenerateIdentity(false))
	random := rand.New(rand.NewPCG(20261021, 2))
	parsePublic := func(text string) error { _, err := ParsePublicKey(text); return err }
	parseIdentity := func(text string) error { _, err := ParseIdentity(text, IdentityOptions{}); return err }
	for key, parse := range map[string]func(string) error{
		identity.PublicKey.Token:   parsePublic,
		readOnlyToken(t, identity): parsePublic,
		identity.Secret:            parseIdentity,
	} {
		for range 200 {
			position := random.IntN(len(key))
			replacement := "qpzry9x8gf2tvdw0s3jn54khce6mua7lQPZRY0"[random.IntN(38)]
			changed := key[:position] + string(replacement) + key[position+1:]
			if !strings.EqualFold(changed, key) {
				if err := parse(changed); attempt(t, err) == nil {
					t.Fatalf("accepted %s", changed)
				}
			}
		}
	}
}

func TestRandomFileEdits(t *testing.T) {
	document, people := sampleDocument(t)
	text := SerializeDocument(document)
	random := rand.New(rand.NewPCG(20261021, 3))
	replacements := []rune(`aZ09+/"{}[],:\ é`)
	for index := range fuzzCases() {
		position := random.IntN(len(text))
		edited := text[:position] + string(replacements[random.IntN(len(replacements))]) + text[position+1:]
		parsed, err := ParseDocumentText(edited, "")
		if attempt(t, err) != nil {
			continue
		}
		// Whatever survived validation must still never reveal a value it does not authenticate.
		for _, environment := range []string{"development", "production"} {
			cell, err := InspectCell(parsed, "DATABASE_URL", environment)
			if attempt(t, err) != nil {
				continue
			}
			value, err := reveal(parsed, people.alice, "DATABASE_URL", environment)
			attempt(t, err)
			if cell.State == StateInvalid && err == nil {
				t.Fatalf("case %d: an invalid value was revealed", index)
			}
			if err == nil && value != map[string]string{"development": "postgres://dev", "production": "postgres://prod"}[environment] {
				t.Fatalf("case %d: other value %q", index, value)
			}
		}
	}
}

func TestOversizedFiles(t *testing.T) {
	_, err := ParseDocumentText(strings.Repeat(" ", MaxFileSize+1), "")
	expectError(t, err, CodeInvalidFile, "larger than 64 MiB")
}

func TestEnvironmentRecipientLimit(t *testing.T) {
	document := CreateDocument()
	names := make([]string, MaxStanzas+1)
	for index := range names {
		names[index] = fmt.Sprintf("r%d", index)
		must[*RecipientEntry](t)(AddRecipient(document, names[index], readOnlyToken(t, must[*Identity](t)(GenerateIdentity(false))), ""))
	}
	check(t, AddEnvironment(document, "big", names))
	_, err := ParseDocumentText(SerializeDocument(document), "")
	expectError(t, err, CodeInvalidFile, "At most 1024 recipients")
}
