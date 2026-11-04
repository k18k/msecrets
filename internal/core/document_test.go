package core

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func issuesOf(input any) []string {
	_, issues := ValidateDocument(input)
	lines := make([]string, len(issues))
	for index, issue := range issues {
		lines[index] = issue.Path + ": " + issue.Message
	}
	return lines
}

func TestValidRoundTrip(t *testing.T) {
	document, _ := sampleDocument(t)
	text := SerializeDocument(document)
	if issues := issuesOf(must[any](t)(ParseJSON(text))); len(issues) > 0 {
		t.Fatal(issues)
	}
	equal(t, SerializeDocument(must[*Document](t)(ParseDocumentText(text, ""))), text)
}

func TestCanonicalSerialization(t *testing.T) {
	document, _ := sampleDocument(t)
	shuffled := parseJSONValue(t, SerializeDocument(document))
	reordered := &Map[any]{}
	for _, key := range []string{"secrets", "environments", "id", "recipients", "version"} {
		value, _ := shuffled.Get(key)
		reordered.Set(key, value)
	}
	text := SerializeDocument(must[*Document](t)(ParseDocument(reordered, "")))
	equal(t, text, SerializeDocument(document))
	if !strings.HasSuffix(text, "}\n") {
		t.Fatal("missing trailing newline")
	}
	equal(t, strings.Join(parseJSONValue(t, text).Keys(), ","), "$schema,version,id,recipients,environments,secrets")
	schema, _ := parseJSONValue(t, text).Get("$schema")
	equal(t, schema.(string), SchemaURL)
}

func TestLegacyVersions(t *testing.T) {
	legacy := parseJSONValue(t, `{"version":"2.0.0","environments":[],"keys":[],"secrets":{}}`)
	issues := issuesOf(legacy)
	if len(issues) != 1 || !strings.Contains(issues[0], "msecrets v2 file; msecrets v4 uses a new format") {
		t.Fatal(issues)
	}
	if issues := issuesOf(parseJSONValue(t, `{"version":5}`)); !strings.Contains(issues[0], "Unsupported format version 5") {
		t.Fatal(issues)
	}
	if issues := issuesOf(parseJSONValue(t, `{}`)); !strings.Contains(issues[0], "Unsupported format version undefined") {
		t.Fatal(issues)
	}
}

func TestStructuralIssues(t *testing.T) {
	document, people := sampleDocument(t)
	input := parseJSONValue(t, SerializeDocument(document))
	input.Set("id", "nope")
	input.Set("extra", true)
	recipients := object(input, "recipients")
	recipients.Set("Bad Name", must[any](t)(ParseJSON(`{"key":"`+people.carol.PublicKey.Token+`"}`)))
	recipients.Set("dup", must[any](t)(ParseJSON(`{"key":"`+people.alice.PublicKey.Token+`"}`)))
	recipients.Set("upper", must[any](t)(ParseJSON(`{"key":"`+strings.ToUpper(readOnlyToken(t, people.carol))+`"}`)))
	development := object(input, "environments", "development")
	list, _ := development.Get("recipients")
	development.Set("recipients", append(list.([]any), "ghost", "alice"))
	values := object(input, "secrets", "DATABASE_URL", "values")
	devValue, _ := values.Get("development")
	values.Set("staging", must[any](t)(ParseJSON(jsStringify(devValue, ""))))
	production := object(values, "production")
	production.Set("sig", "short")
	production.Set("by", "nobody")
	devObject := object(values, "development")
	devObject.Set("data", base64.StdEncoding.EncodeToString([]byte("not age")))
	devObject.Set("to", "ABC")
	debug := object(input, "secrets", "DEBUG")
	debug.Set("environments", []any{})
	debug.Set("description", " padded ")
	object(input, "secrets").Set("1BAD", must[any](t)(ParseJSON(`{"values":{}}`)))

	issues := strings.Join(issuesOf(input), "\n")
	for _, expected := range []string{
		`(?m)^\$\.id: Expected a 32 character lowercase hex file id`,
		`(?m)^\$\.extra: Unknown property`,
		`(?m)^\$\.recipients\.Bad Name: Invalid recipient name`,
		`(?m)^\$\.recipients\.dup\.key: Same key as recipient "alice"`,
		`(?m)^\$\.recipients\.upper\.key: Public key is not in canonical form`,
		`(?m)^\$\.environments\.development\.recipients\[2\]: Unknown recipient "ghost"`,
		`(?m)^\$\.environments\.development\.recipients\[3\]: Duplicate recipient "alice"`,
		`(?m)^\$\.secrets\.DATABASE_URL\.values\.staging: Unknown environment "staging"`,
		`(?m)^\$\.secrets\.DATABASE_URL\.values\.production\.sig: Expected a base64 Ed25519 signature`,
		`(?m)^\$\.secrets\.DATABASE_URL\.values\.production\.by: Unknown recipient "nobody"`,
		`(?m)^\$\.secrets\.DATABASE_URL\.values\.development\.data: Expected a base64-encoded age file`,
		`(?m)^\$\.secrets\.DATABASE_URL\.values\.development\.to: Expected a 32 character`,
		`(?m)^\$\.secrets\.DEBUG\.environments: Must list at least one environment`,
		`(?m)^\$\.secrets\.DEBUG\.description: Descriptions must be non-empty, trimmed`,
		`(?m)^\$\.secrets\.1BAD: Invalid secret name`,
	} {
		if !regexp.MustCompile(expected).MatchString(issues) {
			t.Errorf("missing issue %s\n%s", expected, issues)
		}
	}
}

func TestWrongTypes(t *testing.T) {
	for _, input := range []any{nil, []any{}} {
		if issues := issuesOf(input); !strings.Contains(issues[0], "$: Expected an object") {
			t.Fatal(issues)
		}
	}
	if issues := issuesOf(parseJSONValue(t, `{"version":4,"id":1,"recipients":[],"environments":"x","secrets":{}}`)); len(issues) < 3 {
		t.Fatal(issues)
	}
}

func TestParseErrors(t *testing.T) {
	_, err := ParseDocumentText("{", "x.json")
	expectError(t, err, CodeInvalidFile, `Invalid x\.json`)
	_, err = ParseDocument(parseJSONValue(t, `{"version":4}`), "")
	expectError(t, err, CodeInvalidFile, "")
}

func TestStrictJSON(t *testing.T) {
	document, _ := sampleDocument(t)
	text := SerializeDocument(document)
	for name, bad := range map[string]string{
		"duplicate key":   strings.Replace(text, `"version": 4,`, `"version": 4, "version": 4,`, 1),
		"invalid UTF-8":   strings.Replace(text, `"version"`, "\"version\xff\"", 1),
		"lone surrogate":  strings.Replace(text, `"secrets": {`, `"secrets": {"\ud800": {"values": {}},`, 1),
		"trailing comma":  strings.Replace(text, `"version": 4,`, `"version": 4,,`, 1),
		"byte order mark": "\xef\xbb\xbf" + text,
		"trailing data":   text + "x",
		"deep nesting":    strings.Repeat("[", 1000) + strings.Repeat("]", 1000),
	} {
		if _, err := ParseDocumentText(bad, ""); !IsError(err, CodeInvalidFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPrototypeNames(t *testing.T) {
	equal(t, NameProblem(SecretName, "__proto__"), `"__proto__" is reserved`)
	equal(t, NameProblem(SecretName, "constructor"), "")
	document, _ := sampleDocument(t)
	equal(t, document.Secrets.Has("constructor"), false)
	text := strings.Replace(SerializeDocument(document), `"secrets": {`, "\"secrets\": {\n    \"__proto__\": { \"values\": {} },", 1)
	if !strings.Contains(strings.Join(issuesOf(must[any](t)(ParseJSON(text))), "\n"), "__proto__") {
		t.Fatal("__proto__ accepted")
	}
}

func TestNames(t *testing.T) {
	for _, valid := range []string{"A", "_X", "DATABASE_URL", "lower_case", "A1"} {
		equal(t, NameProblem(SecretName, valid), "")
	}
	for _, invalid := range []string{"", "1A", "A-B", "A.B", "A B", "Ä", strings.Repeat("X", 129)} {
		if NameProblem(SecretName, invalid) == "" {
			t.Error(invalid)
		}
	}
	equal(t, NameProblem(EnvironmentName, "us-east-1.prod"), "")
	equal(t, NameProblem(RecipientName, "alice@example.com"), "")
	equal(t, NameProblem(RecipientName, "ci+deploy"), "")
	for kind, name := range map[NameKind]string{EnvironmentName: "Production", RecipientName: "Alice"} {
		if NameProblem(kind, name) == "" {
			t.Error(name)
		}
	}
	if NameProblem(EnvironmentName, "-dev") == "" {
		t.Error("-dev")
	}
}

func TestSchemaPatterns(t *testing.T) {
	schemaText, err := os.ReadFile(filepath.Join("..", "..", "schema", "v4.json"))
	check(t, err)
	schema := parseJSONValue(t, string(schemaText))
	pattern := func(section string) *regexp.Regexp {
		names, _ := object(schema, "properties", section).Get("propertyNames")
		text, _ := names.(*Map[any]).Get("pattern")
		return regexp.MustCompile(text.(string))
	}
	samples := []string{"A", "_X", "DATABASE_URL", "a", "dev", "us-east-1.prod", "alice@example.com", "ci+deploy", "-x", "1A", "A-B", "Alice", "x.", ""}
	for section, kind := range map[string]NameKind{"secrets": SecretName, "environments": EnvironmentName, "recipients": RecipientName} {
		for _, sample := range samples {
			equal(t, pattern(section).MatchString(sample), NameProblem(kind, sample) == "")
		}
	}

	keyPattern, _ := object(schema, "properties", "recipients", "additionalProperties", "properties", "key").Get("pattern")
	key := regexp.MustCompile(keyPattern.(string))
	document, _ := sampleDocument(t)
	for _, entry := range document.Recipients.Values() {
		if !key.MatchString(entry.Key) {
			t.Error(entry.Key)
		}
	}
	plain, err := os.ReadFile(filepath.Join("..", "..", "packages", "core", "test", "fixtures", "ssh", "plain.pub"))
	check(t, err)
	if line := strings.Join(strings.Fields(string(plain))[:2], " "); !key.MatchString(line) {
		t.Error(line)
	}
}

const escape = "\x1b]52;c;cHduZWQ=\x07\x1b[2K"

func TestDescriptionsRejectControlCharacters(t *testing.T) {
	document, _ := sampleDocument(t)
	input := parseJSONValue(t, SerializeDocument(document))
	object(input, "secrets", "DATABASE_URL").Set("description", "Primary"+escape)
	if !strings.Contains(strings.Join(issuesOf(input), "\n"), "must not contain control characters") {
		t.Fatal("control characters accepted")
	}
	expectError(t, DescribeSecret(document, "DATABASE_URL", "x"+escape), CodeUsage, "must not contain control characters")
	expectError(t, DescribeRecipient(document, "alice", "tab\there"), CodeUsage, "must not contain control characters")
}

func TestValidationErrorsAreSanitized(t *testing.T) {
	document, _ := sampleDocument(t)
	input := parseJSONValue(t, SerializeDocument(document))
	object(input, "secrets").Set("EVIL"+escape, must[any](t)(ParseJSON(`{"values":{}}`)))
	_, err := ParseDocument(input, "")
	if err == nil || regexp.MustCompile(`[\x00-\x1f]`).MatchString(strings.ReplaceAll(err.Error(), "\n", "")) {
		t.Fatalf("%q", err)
	}
}

func TestJavaScriptKeyOrder(t *testing.T) {
	document := CreateDocument()
	for _, name := range []string{"b", "10", "a", "2", "0"} {
		check(t, AddEnvironment(document, name, nil))
	}
	equal(t, strings.Join(document.Environments.Keys(), ","), "0,2,10,b,a")
	document.Environments.Rename("b", "1")
	equal(t, strings.Join(document.Environments.Keys(), ","), "0,1,2,10,a")
}
