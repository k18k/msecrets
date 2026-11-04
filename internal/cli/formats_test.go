package cli

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/k18k/msecrets/internal/core"
)

func dotenvMap(t *testing.T, text string) map[string]string {
	t.Helper()
	entries, err := parseDotenv(text)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, e := range entries {
		values[e.Name] = e.Value
	}
	return values
}

func TestDotenvDialect(t *testing.T) {
	got := dotenvMap(t, strings.Join([]string{
		"# comment", "  A=1", "export B = spaced value   # trailing comment", `C="escaped \" quote\tand tab"`,
		`D='literal \n stays'`, "E=`backtick`", `F="multi`, `line"`, "G=", "H=a#b", "",
	}, "\r\n"))
	want := map[string]string{"A": "1", "B": "spaced value", "C": "escaped \" quote\tand tab", "D": `literal \n stays`,
		"E": "backtick", "F": "multi\nline", "G": "", "H": "a#b"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
}

func TestDotenvErrors(t *testing.T) {
	for text, pattern := range map[string]string{
		"A=1\nnot a pair\n":  `dotenv line 2: expected KEY=value`,
		"A=\"open\n":         `unterminated " quote for A`,
		"A=\"x\" trailing\n": `unexpected characters after the closing quote of A`,
	} {
		_, err := parseDotenv(text)
		if err == nil || !regexp.MustCompile(pattern).MatchString(err.Error()) || !core.IsError(err, core.CodeUsage) {
			t.Fatalf("%q: %v", text, err)
		}
	}
}

func TestDotenvRoundTrip(t *testing.T) {
	values := []entry{
		{"PLAIN", "abc-123_./:@%+,="}, {"SPACES", "a b"}, {"QUOTES", `it's "quoted"`}, {"NEWLINES", "one\ntwo\r\nthree"},
		{"BACKSLASH", `C:\path\n`}, {"HASH", "a #b"}, {"EMPTY", ""}, {"UNICODE", "zażółć 🔐"}, {"CARRIAGE_RETURN", "a\rb"}, {"TAB", "a\tb"},
	}
	parsed, err := parseDotenv(formatDotenv(values))
	if err != nil || !reflect.DeepEqual(parsed, values) {
		t.Fatalf("%q %v", parsed, err)
	}
}

func TestShellQuoting(t *testing.T) {
	if got := formatShell([]entry{{"A", "it's $HOME"}}); got != "export A='it'\\''s $HOME'\n" {
		t.Fatal(got)
	}
	if got := formatPowerShell([]entry{{"A", "it's $env:HOME"}}); got != "$env:A = 'it''s $env:HOME'\n" {
		t.Fatal(got)
	}
	if got, _ := formatJSON(nil); got != "{}\n" {
		t.Fatal(got)
	}
	if got, _ := formatJSON([]entry{{"B", "<&>"}, {"A", "1"}}); got != "{\n  \"B\": \"<&>\",\n  \"A\": \"1\"\n}\n" {
		t.Fatalf("%q", got)
	}
}
