package policy

import (
	"strings"
	"unicode"
)

// FoldKey returns the form of a context key under the case folding a
// Request lookup uses: two keys have the same FoldKey exactly when
// strings.EqualFold holds for them. strings.ToLower is not that folding
// (it keeps U+017F, which EqualFold matches to "s"), so a filter of
// server-set keys must compare FoldKeys.
func FoldKey(k string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		return least
	}, k)
}

// KeySet holds context keys and matches them as a Request lookup does.
type KeySet struct {
	keys     map[string]bool
	prefixes []string
}

// NewKeySet returns the set of keys, each of which may end in "*" to
// name every key with that prefix.
func NewKeySet(keys ...string) KeySet {
	s := KeySet{keys: make(map[string]bool, len(keys))}
	for _, k := range keys {
		if p, ok := strings.CutSuffix(k, "*"); ok {
			s.prefixes = append(s.prefixes, FoldKey(p))
		} else {
			s.keys[FoldKey(k)] = true
		}
	}
	return s
}

// Has reports whether a Request lookup of a key in s could find k.
func (s KeySet) Has(k string) bool {
	f := FoldKey(k)
	if s.keys[f] {
		return true
	}
	for _, p := range s.prefixes {
		if strings.HasPrefix(f, p) {
			return true
		}
	}
	return false
}
