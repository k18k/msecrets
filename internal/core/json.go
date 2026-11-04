package core

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// JSON values as produced by [ParseJSON]: *Map[any] for objects, []any for
// arrays, string, float64, bool, and nil for null.

const maxJSONDepth = 64

type jsonParser struct {
	text  string
	pos   int
	depth int
}

// ParseJSON parses JSON strictly: valid UTF-8 only, no duplicate keys, no lone
// surrogates, and at most 64 levels of nesting. Object key order follows [Map].
func ParseJSON(text string) (any, error) {
	if !utf8.ValidString(text) {
		return nil, fmt.Errorf("Invalid UTF-8")
	}
	p := &jsonParser{text: text}
	value, err := p.value()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.pos < len(p.text) {
		return nil, p.unexpected()
	}
	return value, nil
}

func (p *jsonParser) unexpected() error {
	if p.pos >= len(p.text) {
		return fmt.Errorf("Unexpected end of JSON input")
	}
	r, _ := utf8.DecodeRuneInString(p.text[p.pos:])
	return fmt.Errorf("Unexpected token %s at position %d", jsQuote(string(r)), p.pos)
}

func (p *jsonParser) space() {
	for p.pos < len(p.text) && strings.IndexByte(" \t\n\r", p.text[p.pos]) >= 0 {
		p.pos++
	}
}

func (p *jsonParser) consume(literal string) bool {
	if strings.HasPrefix(p.text[p.pos:], literal) {
		p.pos += len(literal)
		return true
	}
	return false
}

func (p *jsonParser) value() (any, error) {
	p.space()
	if p.pos >= len(p.text) {
		return nil, p.unexpected()
	}
	switch c := p.text[p.pos]; {
	case c == '{' || c == '[':
		p.depth++
		if p.depth > maxJSONDepth {
			return nil, fmt.Errorf("Nested too deeply at position %d", p.pos)
		}
		defer func() { p.depth-- }()
		if c == '{' {
			return p.object()
		}
		return p.array()
	case c == '"':
		return p.string()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case p.consume("true"):
		return true, nil
	case p.consume("false"):
		return false, nil
	case p.consume("null"):
		return nil, nil
	}
	return nil, p.unexpected()
}

func (p *jsonParser) object() (any, error) {
	object := &Map[any]{}
	p.pos++
	p.space()
	if p.consume("}") {
		return object, nil
	}
	for {
		p.space()
		start := p.pos
		if p.pos >= len(p.text) || p.text[p.pos] != '"' {
			return nil, p.unexpected()
		}
		key, err := p.string()
		if err != nil {
			return nil, err
		}
		if object.Has(key) {
			return nil, fmt.Errorf("Duplicate key %s at position %d", jsQuote(key), start)
		}
		p.space()
		if !p.consume(":") {
			return nil, p.unexpected()
		}
		value, err := p.value()
		if err != nil {
			return nil, err
		}
		object.Set(key, value)
		p.space()
		if p.consume("}") {
			return object, nil
		}
		if !p.consume(",") {
			return nil, p.unexpected()
		}
	}
}

func (p *jsonParser) array() (any, error) {
	array := []any{}
	p.pos++
	p.space()
	if p.consume("]") {
		return array, nil
	}
	for {
		value, err := p.value()
		if err != nil {
			return nil, err
		}
		array = append(array, value)
		p.space()
		if p.consume("]") {
			return array, nil
		}
		if !p.consume(",") {
			return nil, p.unexpected()
		}
	}
}

func (p *jsonParser) hex4() (rune, bool) {
	if p.pos+4 > len(p.text) {
		return 0, false
	}
	n, err := strconv.ParseUint(p.text[p.pos:p.pos+4], 16, 32)
	if err != nil {
		return 0, false
	}
	p.pos += 4
	return rune(n), true
}

func (p *jsonParser) string() (string, error) {
	p.pos++
	var b strings.Builder
	for {
		if p.pos >= len(p.text) {
			return "", fmt.Errorf("Unterminated string in JSON at position %d", p.pos)
		}
		c := p.text[p.pos]
		switch {
		case c == '"':
			p.pos++
			return b.String(), nil
		case c < 0x20:
			return "", fmt.Errorf("Bad control character in string literal in JSON at position %d", p.pos)
		case c != '\\':
			b.WriteByte(c)
			p.pos++
			continue
		}
		start := p.pos
		p.pos++
		if p.pos >= len(p.text) {
			return "", p.unexpected()
		}
		escape := p.text[p.pos]
		p.pos++
		if i := strings.IndexByte(`"\/bfnrt`, escape); i >= 0 {
			b.WriteByte("\"\\/\b\f\n\r\t"[i])
			continue
		}
		if escape != 'u' {
			return "", fmt.Errorf("Bad escaped character in JSON at position %d", start)
		}
		r, ok := p.hex4()
		if !ok {
			return "", fmt.Errorf("Bad Unicode escape in JSON at position %d", start)
		}
		if utf16.IsSurrogate(r) {
			low := rune(0)
			if r < 0xdc00 && p.consume(`\u`) {
				if low, ok = p.hex4(); !ok {
					return "", fmt.Errorf("Bad Unicode escape in JSON at position %d", p.pos)
				}
			}
			if r = utf16.DecodeRune(r, low); r == utf8.RuneError {
				return "", fmt.Errorf("Lone surrogate in JSON at position %d", start)
			}
		}
		b.WriteRune(r)
	}
}

func (p *jsonParser) number() (any, error) {
	start := p.pos
	digits := func() int {
		begin := p.pos
		for p.pos < len(p.text) && p.text[p.pos] >= '0' && p.text[p.pos] <= '9' {
			p.pos++
		}
		return p.pos - begin
	}
	p.consume("-")
	if !p.consume("0") && digits() == 0 {
		return nil, p.unexpected()
	}
	if p.consume(".") && digits() == 0 {
		return nil, p.unexpected()
	}
	if p.consume("e") || p.consume("E") {
		if !p.consume("+") {
			p.consume("-")
		}
		if digits() == 0 {
			return nil, p.unexpected()
		}
	}
	// Out of range values become ±Inf or 0, as in JavaScript.
	value, _ := strconv.ParseFloat(p.text[start:p.pos], 64)
	return value, nil
}

// jsQuote quotes a string like JavaScript's JSON.stringify.
func jsQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// jsNumber formats a number like JavaScript's JSON.stringify.
func jsNumber(f float64) string {
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "null"
	}
	if f == 0 {
		return "0"
	}
	if abs := math.Abs(f); abs >= 1e21 || abs < 1e-6 {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		mantissa, exponent, _ := strings.Cut(s, "e")
		sign := exponent[:1]
		exponent = strings.TrimLeft(exponent[1:], "0")
		return mantissa + "e" + sign + exponent
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// jsStringify serializes a JSON value like JavaScript's JSON.stringify(value, null, indent).
func jsStringify(value any, indent string) string {
	var b strings.Builder
	writeJSON(&b, value, indent, "\n")
	return b.String()
}

func writeJSON(b *strings.Builder, value any, indent, newline string) {
	inner, closing, separator := newline+indent, newline, ": "
	if indent == "" {
		inner, closing, separator = "", "", ":"
	}
	switch v := value.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(v))
	case float64:
		b.WriteString(jsNumber(v))
	case string:
		b.WriteString(jsQuote(v))
	case []any:
		if len(v) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(inner)
			writeJSON(b, item, indent, inner)
		}
		b.WriteString(closing)
		b.WriteByte(']')
	case *Map[any]:
		if v.Len() == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, key := range v.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(inner)
			b.WriteString(jsQuote(key))
			b.WriteString(separator)
			writeJSON(b, v.values[key], indent, inner)
		}
		b.WriteString(closing)
		b.WriteByte('}')
	default:
		panic(fmt.Sprintf("core: not a JSON value: %T", value))
	}
}
