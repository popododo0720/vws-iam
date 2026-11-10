package iam_test

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

func TestLegacyRootKeyValidation(t *testing.T) {
	const legacy = "VWSABCDEF012389XYZAB"
	for _, tc := range []struct {
		name, id    string
		root, valid bool
	}{
		{"legacy root", legacy, true, true},
		{"legacy IAM user", legacy, false, false},
		{"short", legacy[:19], true, false},
		{"long", legacy + "A", true, false},
		{"lowercase", "VWSaBCDEF012389XYZAB", true, false},
		{"symbol", "VWS-BCDEF012389XYZAB", true, false},
		{"generated", "AKIAABCDEFGHIJKLMNOP", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := iam.AccessKey{
				ID: tc.id, Root: tc.root, Status: iam.KeyActive,
				Secret: iam.Sealed{KeyID: "k", Ciphertext: []byte{1}},
			}
			if !tc.root {
				k.UserName = "alice"
			}
			if err := k.Validate(); (err == nil) != tc.valid {
				t.Fatalf("key valid=%v, want %v", err == nil, tc.valid)
			}
		})
	}
	if err := (iam.KeyIndex{ID: legacy, Project: "acme"}).Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (iam.KeyIndex{ID: legacy, Project: "acme", Expires: time.Now()}).Validate(); err == nil {
		t.Fatal("legacy session index accepted")
	}
}
