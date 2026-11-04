package core

import (
	"encoding/json/jsontext"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// JSON values as produced by [ParseJSON]: *Map[any] for objects, []any for
// arrays, string, float64, bool, and nil for null.

const maxJSONDepth = 64

// ParseJSON parses JSON strictly (encoding/json/jsontext defaults: valid UTF-8,
// no lone surrogates, no duplicate names) with at most 64 levels of nesting.
// Object key order follows [Map].
func ParseJSON(text string) (any, error) {
	decoder := jsontext.NewDecoder(strings.NewReader(text))
	value, err := readJSON(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.ReadToken(); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("unexpected data after the top-level value at position %d", decoder.InputOffset())
		}
		return nil, err
	}
	return value, nil
}

func readJSON(decoder *jsontext.Decoder) (any, error) {
	token, err := decoder.ReadToken()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if decoder.StackDepth() > maxJSONDepth {
		return nil, fmt.Errorf("nested too deeply at position %d", decoder.InputOffset())
	}
	switch token.Kind() {
	case 'n':
		return nil, nil
	case 't', 'f':
		return token.Bool(), nil
	case '"':
		return token.String(), nil
	case '0':
		// Out of range values become ±Inf, as in JavaScript.
		value, _ := strconv.ParseFloat(token.String(), 64)
		return value, nil
	case '[':
		array := []any{}
		for decoder.PeekKind() != ']' {
			item, err := readJSON(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, item)
		}
		_, err := decoder.ReadToken()
		return array, err
	case '{':
		object := &Map[any]{}
		for decoder.PeekKind() != '}' {
			name, err := decoder.ReadToken()
			if err != nil {
				return nil, err
			}
			key := name.String()
			value, err := readJSON(decoder)
			if err != nil {
				return nil, err
			}
			object.Set(key, value)
		}
		_, err := decoder.ReadToken()
		return object, err
	}
	return nil, fmt.Errorf("unexpected token %v", token)
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
