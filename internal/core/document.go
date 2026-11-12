package core

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// The msecrets.json v4 file format: the compatibility contract of msecrets.
// Structural validation lives here; cryptographic state (signatures, drift,
// completeness) is evaluated by status.go.

const (
	// FormatVersion is the version of the file format.
	FormatVersion = 4
	// DefaultFilename is the name of the secrets file.
	DefaultFilename = "msecrets.json"
	// SchemaURL is written as "$schema" into every file.
	SchemaURL = "https://raw.githubusercontent.com/k18k/msecrets/master/schema/v4.json"
	// MaxFileSize bounds parsing and signature checks of untrusted files.
	MaxFileSize = 64 * 1024 * 1024
)

// RecipientEntry is a named public key.
type RecipientEntry struct {
	// Key is the public key token: msecrets1…, age1…, age1pq1…, or ssh-ed25519 AAAA….
	Key string
	// Description is optional ("" means none).
	Description string
}

// EnvironmentEntry lists who can read (and, with a signing key, write) an environment.
type EnvironmentEntry struct {
	Recipients []string
}

// SealedValue is one encrypted and signed value.
type SealedValue struct {
	// To is the digest of the recipient keys the value is encrypted to.
	To string
	// By is the name of the recipient that signed the value.
	By string
	// Sig is the Ed25519 signature (base64) over the value binding.
	Sig string
	// Data is the age-encrypted value (base64).
	Data string
}

// SecretEntry is a secret and its values per environment.
type SecretEntry struct {
	// Description is optional ("" means none).
	Description string
	// Environments the secret applies to; nil means every environment.
	Environments []string
	Values       Map[*SealedValue]
}

// Document is a parsed msecrets.json file.
type Document struct {
	// ID is the random file identifier, bound into every value signature.
	ID           string
	Recipients   Map[*RecipientEntry]
	Environments Map[*EnvironmentEntry]
	Secrets      Map[*SecretEntry]
}

// ValidationIssue is one problem found by [ValidateDocument].
type ValidationIssue struct {
	Path    string
	Message string
}

// NameKind is the kind of a name: "secret", "environment", or "recipient".
type NameKind string

// Name kinds.
const (
	SecretName      NameKind = "secret"
	EnvironmentName NameKind = "environment"
	RecipientName   NameKind = "recipient"
)

var nameRules = map[NameKind]struct {
	pattern     *regexp.Regexp
	description string
}{
	SecretName: {
		regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`),
		"letters, digits, and underscores, not starting with a digit (a valid environment variable name)",
	},
	EnvironmentName: {
		regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$`),
		"lowercase letters, digits, '.', '_', and '-', starting and ending with a letter or digit",
	},
	RecipientName: {
		regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._@+-]{0,62}[a-z0-9])?$`),
		"lowercase letters, digits, '.', '_', '@', '+', and '-', starting and ending with a letter or digit",
	},
}

// NameProblem describes why name is not a valid name of the kind, or returns "".
func NameProblem(kind NameKind, name string) string {
	if name == "__proto__" {
		return `"__proto__" is reserved`
	}
	rule := nameRules[kind]
	if rule.pattern.MatchString(name) {
		return ""
	}
	return fmt.Sprintf("Invalid %s name %s: use %s", kind, jsQuote(name), rule.description)
}

// RequireName returns a USAGE error if name is not a valid name of the kind.
func RequireName(kind NameKind, name string) error {
	if problem := NameProblem(kind, name); problem != "" {
		return newError(CodeUsage, "%s", problem)
	}
	return nil
}

// isControl matches the characters that could rewrite what a terminal shows (escape sequence injection).
func isControl(r rune) bool { return r <= 0x1f || (r >= 0x7f && r <= 0x9f) }

// sanitize replaces control characters (and invalid UTF-8) with U+FFFD, for printing untrusted text.
func sanitize(text string) string {
	return strings.Map(func(r rune) rune {
		if isControl(r) {
			return utf8.RuneError
		}
		return r
	}, strings.ToValidUTF8(text, "�"))
}

// isJSSpace matches the characters that JavaScript's String.prototype.trim removes.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func jsTrim(text string) string { return strings.TrimFunc(text, isJSSpace) }

// DescriptionProblem describes why text is not a valid description, or returns "".
func DescriptionProblem(text string) string {
	if text == "" || text != jsTrim(text) || len(utf16.Encode([]rune(text))) > 1000 {
		return "Descriptions must be non-empty, trimmed, and at most 1000 characters"
	}
	if !utf8.ValidString(text) || strings.ContainsFunc(text, isControl) {
		return "Descriptions must not contain control characters"
	}
	return ""
}

// NormalizeDescription trims a description for storage ("" means none), or returns a USAGE error.
func NormalizeDescription(description string) (string, error) {
	text := jsTrim(description)
	if text == "" {
		return "", nil
	}
	if problem := DescriptionProblem(text); problem != "" {
		return "", newError(CodeUsage, "%s", problem)
	}
	return text, nil
}

// CreateDocument returns an empty document with a new random id.
func CreateDocument() *Document {
	return &Document{ID: randomHex(16)}
}

func randomBytes(size int) []byte {
	bytes := make([]byte, size)
	rand.Read(bytes)
	return bytes
}

func randomHex(size int) string { return hex.EncodeToString(randomBytes(size)) }

type validator struct {
	issues []ValidationIssue
}

func (v *validator) issue(path, format string, args ...any) {
	v.issues = append(v.issues, ValidationIssue{Path: path, Message: fmt.Sprintf(format, args...)})
}

// object checks that value is an object with the required keys and no unknown keys.
func (v *validator) object(value any, path string, required, optional []string) *Map[any] {
	object, ok := value.(*Map[any])
	if !ok || object == nil {
		v.issue(path, "Expected an object")
		return nil
	}
	for _, key := range required {
		if !object.Has(key) {
			v.issue(path, "Missing property \"%s\"", key)
		}
	}
	for _, key := range object.keys {
		if !slices.Contains(required, key) && !slices.Contains(optional, key) {
			v.issue(path+"."+key, "Unknown property")
		}
	}
	return object
}

func (v *validator) string(value any, path string) (string, bool) {
	text, ok := value.(string)
	if !ok {
		v.issue(path, "Expected a string")
	}
	return text, ok
}

func (v *validator) description(object *Map[any], path string) string {
	value, present := object.Get("description")
	if !present {
		return ""
	}
	text, ok := v.string(value, path)
	if problem := DescriptionProblem(text); ok && problem != "" {
		v.issue(path, "%s", problem)
	}
	return text
}

// record returns the entries of an object whose names are valid names of the kind.
func (v *validator) record(value any, path string, kind NameKind) []string {
	object, ok := value.(*Map[any])
	if !ok || object == nil {
		v.issue(path, "Expected an object")
		return nil
	}
	var names []string
	for _, name := range object.keys {
		if problem := NameProblem(kind, name); problem != "" {
			v.issue(path+"."+name, "%s", problem)
		} else {
			names = append(names, name)
		}
	}
	return names
}

func (v *validator) nameList(value any, path string, known func(string) bool, what string) []string {
	array, ok := value.([]any)
	if !ok {
		v.issue(path, "Expected an array")
		return []string{}
	}
	names := []string{}
	for index, entry := range array {
		name, ok := entry.(string)
		switch {
		case !ok || !known(name):
			v.issue(fmt.Sprintf("%s[%d]", path, index), "Unknown %s %s", what, jsStringify(entry, ""))
		case slices.Contains(names, name):
			v.issue(fmt.Sprintf("%s[%d]", path, index), "Duplicate %s \"%s\"", what, name)
		default:
			names = append(names, name)
		}
	}
	return names
}

func (v *validator) recipient(value any, path string) (*RecipientEntry, string) {
	entry := v.object(value, path, []string{"key"}, []string{"description"})
	if entry == nil {
		return nil, ""
	}
	field, _ := entry.Get("key")
	key, ok := v.string(field, path+".key")
	if !ok {
		return nil, ""
	}
	keyID := key
	if parsed, err := ParsePublicKey(key); err != nil {
		v.issue(path+".key", "%s", err.Error())
	} else {
		keyID = parsed.id()
		if parsed.Token != key {
			v.issue(path+".key", "Public key is not in canonical form; expected \"%s\"", parsed.Token)
		}
	}
	return &RecipientEntry{Key: key, Description: v.description(entry, path+".description")}, keyID
}

// isPaddedBase64 matches standard base64 with padding (any trailing bits).
func isPaddedBase64(text string) bool {
	if len(text)%4 != 0 {
		return false
	}
	body := strings.TrimSuffix(strings.TrimSuffix(text, "="), "=")
	return len(text)-len(body) <= 2 && containsOnly(body, base64Alphabet)
}

var lowerHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (v *validator) value(value any, path string, recipients *Map[*RecipientEntry]) *SealedValue {
	entry := v.object(value, path, []string{"to", "by", "sig", "data"}, nil)
	if entry == nil {
		return nil
	}
	field := func(name string) (string, bool) {
		value, _ := entry.Get(name)
		return v.string(value, path+"."+name)
	}
	to, okTo := field("to")
	by, okBy := field("by")
	sig, okSig := field("sig")
	data, okData := field("data")

	if okTo && !lowerHex32.MatchString(to) {
		v.issue(path+".to", "Expected a 32 character lowercase hex recipient digest")
	}
	if okBy && !recipients.Has(by) {
		v.issue(path+".by", "Unknown recipient \"%s\"", by)
	}
	if okSig && !(isPaddedBase64(sig) && base64.StdEncoding.DecodedLen(len(sig))-strings.Count(sig, "=") == 64) {
		v.issue(path+".sig", "Expected a base64 Ed25519 signature")
	}
	if okData && !isAgeData(data) {
		v.issue(path+".data", "Expected a base64-encoded age file")
	}
	if !okTo || !okBy || !okSig || !okData {
		return nil
	}
	return &SealedValue{To: to, By: by, Sig: sig, Data: data}
}

// isAgeData reports whether text is padded base64 of something that starts like an age file.
func isAgeData(text string) bool {
	if !isPaddedBase64(text) || len(text) < 32 {
		return false
	}
	prefix, err := base64.StdEncoding.DecodeString(text[:32])
	return err == nil && strings.HasPrefix(string(prefix), ageVersion+"\n")
}

func (v *validator) secret(value any, path string, environments *Map[*EnvironmentEntry], recipients *Map[*RecipientEntry]) *SecretEntry {
	entry := v.object(value, path, []string{"values"}, []string{"description", "environments"})
	if entry == nil {
		return nil
	}
	secret := &SecretEntry{Description: v.description(entry, path+".description")}
	if list, present := entry.Get("environments"); present {
		secret.Environments = v.nameList(list, path+".environments", environments.Has, "environment")
		if len(secret.Environments) == 0 {
			v.issue(path+".environments", "Must list at least one environment; omit it to apply to all environments")
		}
	}
	values, _ := entry.Get("values")
	for _, environment := range v.record(values, path+".values", EnvironmentName) {
		if !environments.Has(environment) {
			v.issue(path+".values."+environment, "Unknown environment \"%s\"", environment)
			continue
		}
		sealed, _ := values.(*Map[any]).Get(environment)
		if parsed := v.value(sealed, path+".values."+environment, recipients); parsed != nil {
			secret.Values.Set(environment, parsed)
		}
	}
	return secret
}

var legacyVersion = regexp.MustCompile(`^[0-3]\.`)

// ValidateDocument validates untrusted input (a value from [ParseJSON]) against
// the v4 format. It returns the document when there are no issues.
func ValidateDocument(input any) (*Document, []ValidationIssue) {
	v := &validator{}

	if object, ok := input.(*Map[any]); ok && object != nil {
		if version, present := object.Get("version"); version != float64(FormatVersion) {
			text, isString := version.(string)
			switch {
			case isString && legacyVersion.MatchString(text):
				v.issue("$.version", "This is a msecrets v%s file; msecrets v4 uses a new format. Re-create it with `msecrets init` and `msecrets import`", text[:1])
			case !present:
				v.issue("$.version", "Unsupported format version undefined; expected %d", FormatVersion)
			default:
				v.issue("$.version", "Unsupported format version %s; expected %d", jsStringify(version, ""), FormatVersion)
			}
			return nil, v.issues
		}
	}

	root := v.object(input, "$", []string{"version", "id", "recipients", "environments", "secrets"}, []string{"$schema"})
	if root == nil {
		return nil, v.issues
	}

	document := &Document{}
	idValue, _ := root.Get("id")
	if id, ok := v.string(idValue, "$.id"); ok {
		document.ID = id
		if !lowerHex32.MatchString(id) {
			v.issue("$.id", "Expected a 32 character lowercase hex file id")
		}
	}

	recipientsValue, _ := root.Get("recipients")
	seenKeys := map[string]string{}
	for _, name := range v.record(recipientsValue, "$.recipients", RecipientName) {
		value, _ := recipientsValue.(*Map[any]).Get(name)
		entry, keyID := v.recipient(value, "$.recipients."+name)
		if entry == nil {
			continue
		}
		if duplicate, ok := seenKeys[keyID]; ok {
			v.issue("$.recipients."+name+".key", "Same key as recipient \"%s\"", duplicate)
		}
		seenKeys[keyID] = name
		document.Recipients.Set(name, entry)
	}

	environmentsValue, _ := root.Get("environments")
	for _, name := range v.record(environmentsValue, "$.environments", EnvironmentName) {
		value, _ := environmentsValue.(*Map[any]).Get(name)
		path := "$.environments." + name
		entry := v.object(value, path, []string{"recipients"}, nil)
		if entry == nil {
			continue
		}
		list, _ := entry.Get("recipients")
		recipients := v.nameList(list, path+".recipients", document.Recipients.Has, "recipient")
		if len(recipients) > MaxStanzas {
			v.issue(path+".recipients", "At most %d recipients", MaxStanzas)
		}
		document.Environments.Set(name, &EnvironmentEntry{Recipients: recipients})
	}

	secretsValue, _ := root.Get("secrets")
	for _, name := range v.record(secretsValue, "$.secrets", SecretName) {
		value, _ := secretsValue.(*Map[any]).Get(name)
		if secret := v.secret(value, "$.secrets."+name, &document.Environments, &document.Recipients); secret != nil {
			document.Secrets.Set(name, secret)
		}
	}

	if len(v.issues) > 0 {
		return nil, v.issues
	}
	return document, nil
}

// FormatIssues renders issues one per line, with control characters replaced.
func FormatIssues(issues []ValidationIssue) string {
	lines := make([]string, len(issues))
	for index, issue := range issues {
		lines[index] = sanitize(fmt.Sprintf("  %s: %s", issue.Path, issue.Message))
	}
	return strings.Join(lines, "\n")
}

func sourceName(source string) string {
	if source == "" {
		return "secrets file"
	}
	return source
}

// ParseDocument validates a JSON value (see [ParseJSON]); source names the input in errors ("" means "secrets file").
func ParseDocument(input any, source string) (*Document, error) {
	document, issues := ValidateDocument(input)
	if document == nil {
		return nil, newError(CodeInvalidFile, "Invalid %s:\n%s", sourceName(source), FormatIssues(issues))
	}
	return document, nil
}

// ParseDocumentText parses and validates the text of a secrets file.
func ParseDocumentText(text, source string) (*Document, error) {
	if len(text) > MaxFileSize {
		return nil, newError(CodeInvalidFile, "Invalid %s: larger than 64 MiB", sourceName(source))
	}
	json, err := ParseJSON(text)
	if err != nil {
		return nil, wrapError(CodeInvalidFile, err, "Invalid %s: %s", sourceName(source), err.Error())
	}
	return ParseDocument(json, source)
}

func sortedKeys[V any](m *Map[V]) []string {
	keys := m.Keys()
	slices.Sort(keys)
	return keys
}

// SerializeDocument renders the canonical file text: fixed field order, sorted
// recipient and secret names, environments in their declared order, two-space
// indentation, and a trailing newline. Byte-identical to the TypeScript implementation.
func SerializeDocument(document *Document) string {
	environmentOrder := document.Environments.Keys()

	recipients := &Map[any]{}
	for _, name := range sortedKeys(&document.Recipients) {
		entry, _ := document.Recipients.Get(name)
		object := &Map[any]{}
		object.Set("key", entry.Key)
		if entry.Description != "" {
			object.Set("description", entry.Description)
		}
		recipients.Set(name, object)
	}

	environments := &Map[any]{}
	for _, name := range environmentOrder {
		entry, _ := document.Environments.Get(name)
		names := slices.Sorted(slices.Values(entry.Recipients))
		list := make([]any, len(names))
		for index, recipient := range names {
			list[index] = recipient
		}
		object := &Map[any]{}
		object.Set("recipients", list)
		environments.Set(name, object)
	}

	secrets := &Map[any]{}
	for _, name := range sortedKeys(&document.Secrets) {
		secret, _ := document.Secrets.Get(name)
		object := &Map[any]{}
		if secret.Description != "" {
			object.Set("description", secret.Description)
		}
		if secret.Environments != nil {
			list := []any{}
			for _, environment := range environmentOrder {
				if slices.Contains(secret.Environments, environment) {
					list = append(list, environment)
				}
			}
			object.Set("environments", list)
		}
		values := &Map[any]{}
		for _, environment := range environmentOrder {
			if value, ok := secret.Values.Get(environment); ok {
				sealed := &Map[any]{}
				sealed.Set("to", value.To)
				sealed.Set("by", value.By)
				sealed.Set("sig", value.Sig)
				sealed.Set("data", value.Data)
				values.Set(environment, sealed)
			}
		}
		object.Set("values", values)
		secrets.Set(name, object)
	}

	root := &Map[any]{}
	root.Set("$schema", SchemaURL)
	root.Set("version", float64(FormatVersion))
	root.Set("id", document.ID)
	root.Set("recipients", recipients)
	root.Set("environments", environments)
	root.Set("secrets", secrets)
	return jsStringify(root, "  ") + "\n"
}

// SecretEnvironments returns the environments a secret is expected to have a value in.
func SecretEnvironments(document *Document, secret *SecretEntry) []string {
	var names []string
	for _, name := range document.Environments.keys {
		if secret.Environments == nil || slices.Contains(secret.Environments, name) {
			names = append(names, name)
		}
	}
	return names
}
