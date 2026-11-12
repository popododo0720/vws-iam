package iam

import (
	"regexp"
	"testing"
	"testing/cryptotest"
)

func TestNewKeyPairIDIsAWSShapedAndUnique(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 499)
	shape := regexp.MustCompile(`^key-[0-9a-f]{17}$`)
	seen := map[string]bool{}
	for range 100000 {
		id := NewKeyPairID()
		if !shape.MatchString(id) {
			t.Fatalf("id %q is not key- and 17 hex digits", id)
		}
		if seen[id] {
			t.Fatalf("id %q minted twice", id)
		}
		seen[id] = true
		if !keyPairIDRE.MatchString(id) {
			t.Fatalf("id %q is refused by the stored id rule", id)
		}
	}
}
