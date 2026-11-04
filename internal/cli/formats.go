package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// entry is a name and a value, in order.
type entry struct{ Name, Value string }

// orderedObject marshals as a JSON object that keeps its key order.
type orderedObject []struct {
	Key   string
	Value any
}

func (o orderedObject) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for index, field := range o {
		if index > 0 {
			b.WriteByte(',')
		}
		key, err := marshal(field.Key)
		if err != nil {
			return nil, err
		}
		value, err := marshal(field.Value)
		if err != nil {
			return nil, err
		}
		b.Write(key)
		b.WriteByte(':')
		b.Write(value)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func (o *orderedObject) add(key string, value any) {
	*o = append(*o, struct {
		Key   string
		Value any
	}{key, value})
}

func marshal(value any) ([]byte, error) {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// jsonText is JSON indented with two spaces, like JSON.stringify(value, null, 2).
func jsonText(value any) (string, error) {
	compact, err := marshal(value)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := json.Indent(&b, compact, "", "  "); err != nil {
		return "", err
	}
	return b.String(), nil
}

var (
	dotenvKey     = regexp.MustCompile(`^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*`)
	dotenvComment = regexp.MustCompile(`\s+#.*$`)
	dotenvEscape  = regexp.MustCompile(`\\([nrt"\\])`)
	plainValue    = regexp.MustCompile(`^[A-Za-z0-9_./:@%+,=-]*$`)
)

// parseDotenv parses dotenv files: KEY=value, optional `export `, # comments,
// single quotes (literal), double quotes (\n, \r, \t, \", \\ escapes), and
// backticks (literal), each of which may span lines. Later keys win.
func parseDotenv(text string) ([]entry, error) {
	source := strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	var entries []entry
	set := func(name, value string) {
		for index := range entries {
			if entries[index].Name == name {
				entries[index].Value = value
				return
			}
		}
		entries = append(entries, entry{name, value})
	}
	lineEnd := func(from int) int {
		if end := strings.IndexByte(source[from:], '\n'); end >= 0 {
			return from + end
		}
		return len(source)
	}
	offset, line := 0, 1
	fail := func(format string, args ...any) error {
		return usageError("dotenv line %d: %s", line, fmt.Sprintf(format, args...))
	}

	for offset < len(source) {
		end := lineEnd(offset)
		rawLine := source[offset:end]
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			offset, line = end+1, line+1
			continue
		}
		match := dotenvKey.FindStringSubmatch(rawLine)
		if match == nil {
			return nil, fail("expected KEY=value, got \"%s\"", trimmed)
		}
		name := match[1]
		cursor := offset + len(match[0])
		var value string

		if quote := byteAt(source, cursor); quote == '"' || quote == '\'' || quote == '`' {
			closing := cursor + 1
			for ; closing < len(source); closing++ {
				if quote == '"' && source[closing] == '\\' {
					closing++
				} else if source[closing] == quote {
					break
				}
			}
			if closing >= len(source) {
				return nil, fail("unterminated %c quote for %s", quote, name)
			}
			inner := source[cursor+1 : closing]
			value = inner
			if quote == '"' {
				value = dotenvEscape.ReplaceAllStringFunc(inner, func(escape string) string {
					switch escape[1] {
					case 'n':
						return "\n"
					case 'r':
						return "\r"
					case 't':
						return "\t"
					}
					return escape[1:]
				})
			}
			line += strings.Count(inner, "\n")
			cursor = closing + 1
			rest := source[cursor:lineEnd(cursor)]
			if restTrimmed := strings.TrimSpace(rest); restTrimmed != "" && !strings.HasPrefix(restTrimmed, "#") {
				return nil, fail("unexpected characters after the closing quote of %s", name)
			}
			cursor += len(rest)
		} else {
			end := lineEnd(cursor)
			value = strings.TrimSpace(dotenvComment.ReplaceAllString(source[cursor:end], ""))
			cursor = end
		}
		set(name, value)
		offset, line = cursor+1, line+1
	}
	return entries, nil
}

func byteAt(text string, index int) byte {
	if index < len(text) {
		return text[index]
	}
	return 0
}

var dotenvQuoted = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)

func formatDotenv(entries []entry) string {
	var b strings.Builder
	for _, e := range entries {
		switch {
		case plainValue.MatchString(e.Value):
			fmt.Fprintf(&b, "%s=%s\n", e.Name, e.Value)
		case !strings.ContainsAny(e.Value, "'\n\r"):
			// Single quotes are literal, but parsers normalize line breaks: CR and LF need escapes.
			fmt.Fprintf(&b, "%s='%s'\n", e.Name, e.Value)
		default:
			fmt.Fprintf(&b, "%s=\"%s\"\n", e.Name, dotenvQuoted.Replace(e.Value))
		}
	}
	return b.String()
}

func formatShell(entries []entry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "export %s='%s'\n", e.Name, strings.ReplaceAll(e.Value, "'", `'\''`))
	}
	return b.String()
}

func formatPowerShell(entries []entry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "$env:%s = '%s'\n", e.Name, strings.ReplaceAll(e.Value, "'", "''"))
	}
	return b.String()
}

func formatJSON(entries []entry) (string, error) {
	object := orderedObject{}
	for _, e := range entries {
		object.add(e.Name, e.Value)
	}
	text, err := jsonText(object)
	return text + "\n", err
}
