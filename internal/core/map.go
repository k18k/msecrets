package core

import (
	"iter"
	"slices"
	"strconv"
)

// Map is a string-keyed map that iterates in JavaScript object key order:
// keys that are array indices ("0", "17") first in ascending numeric order,
// then the other keys in insertion order. The file format relies on this order
// (environments keep their declared order), and matching JavaScript keeps
// serialization byte-identical with the TypeScript implementation.
//
// The zero value is an empty map ready to use. Maps share state when copied;
// use pointers.
type Map[V any] struct {
	keys   []string
	values map[string]V
}

// isArrayIndex reports whether JavaScript treats key as an array index.
func isArrayIndex(key string) bool {
	if key == "" || len(key) > 10 || (len(key) > 1 && key[0] == '0') {
		return false
	}
	n, err := strconv.ParseUint(key, 10, 64)
	return err == nil && n < 1<<32-1
}

func compareIndices(a, b string) int {
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// Len returns the number of entries.
func (m *Map[V]) Len() int { return len(m.keys) }

// Get returns the value for key.
func (m *Map[V]) Get(key string) (V, bool) {
	v, ok := m.values[key]
	return v, ok
}

// Has reports whether key exists.
func (m *Map[V]) Has(key string) bool {
	_, ok := m.values[key]
	return ok
}

// Set adds or replaces an entry. A replaced entry keeps its position.
func (m *Map[V]) Set(key string, value V) {
	if m.values == nil {
		m.values = map[string]V{}
	}
	if _, ok := m.values[key]; !ok {
		position := len(m.keys)
		if isArrayIndex(key) {
			position = 0
			for position < len(m.keys) && isArrayIndex(m.keys[position]) && compareIndices(m.keys[position], key) < 0 {
				position++
			}
		}
		m.keys = slices.Insert(m.keys, position, key)
	}
	m.values[key] = value
}

// Delete removes key and reports whether it existed.
func (m *Map[V]) Delete(key string) bool {
	if _, ok := m.values[key]; !ok {
		return false
	}
	delete(m.values, key)
	m.keys = slices.DeleteFunc(m.keys, func(k string) bool { return k == key })
	return true
}

// Keys returns a copy of the keys in order.
func (m *Map[V]) Keys() []string { return slices.Clone(m.keys) }

// All iterates over the entries in order. The map may be modified during iteration;
// iteration covers the keys present when it started.
func (m *Map[V]) All() iter.Seq2[string, V] {
	return func(yield func(string, V) bool) {
		for _, key := range m.Keys() {
			value, ok := m.values[key]
			if ok && !yield(key, value) {
				return
			}
		}
	}
}

// Values returns the values in order.
func (m *Map[V]) Values() []V {
	values := make([]V, 0, len(m.keys))
	for _, key := range m.keys {
		values = append(values, m.values[key])
	}
	return values
}

// Rename renames a key, keeping its position (as far as JavaScript key order allows).
func (m *Map[V]) Rename(from, to string) {
	var renamed Map[V]
	for _, key := range m.keys {
		target := key
		if key == from {
			target = to
		}
		renamed.Set(target, m.values[key])
	}
	*m = renamed
}
