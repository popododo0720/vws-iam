package iam

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func policyWithTags(tags map[string]string) Policy {
	return Policy{
		Name: "p", ID: "ANPA1", Created: time.Now(),
		DefaultVersion: "v1", NextVersion: 2,
		Versions: []PolicyVersion{{ID: "v1", Document: `{"Version":"2012-10-17","Statement":[]}`}},
		Tags:     tags,
	}
}

func TestPolicyTagValidation(t *testing.T) {
	valid := map[string]string{
		"Team":                            "Platform / SRE: a=b + c @x",
		"Cost Center":                     "12345",
		"lower_case-1":                    "",
		"unicode":                         "Ünïcode",
		strings.Repeat("k", MaxTagKeyLen): "v",
		"maxvalue":                        strings.Repeat("v", MaxTagValueLen),
	}
	if err := policyWithTags(valid).Validate(); err != nil {
		t.Fatalf("valid tags rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		tags map[string]string
	}{
		{"empty key", map[string]string{"": "v"}},
		{"key too long", map[string]string{strings.Repeat("k", MaxTagKeyLen+1): "v"}},
		{"value too long", map[string]string{"k": strings.Repeat("v", MaxTagValueLen+1)}},
		{"bad key character", map[string]string{"bad#key": "v"}},
		{"bad value character", map[string]string{"k": "bad#value"}},
		{"reserved key prefix", map[string]string{"aws:team": "v"}},
		{"reserved key prefix in another case", map[string]string{"AWS:team": "v"}},
		{"reserved value prefix", map[string]string{"k": "aws:value"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := policyWithTags(tc.tags).Validate(); err == nil {
				t.Fatalf("%v accepted", tc.tags)
			}
		})
	}
	tooMany := make(map[string]string, MaxPolicyTags+1)
	for i := 0; i <= MaxPolicyTags; i++ {
		tooMany[strings.Repeat("k", i+1)] = "v"
	}
	if err := policyWithTags(tooMany).Validate(); err == nil {
		t.Fatal("51 tags accepted")
	}
}

func TestCheckTag(t *testing.T) {
	if err := CheckTag("Team", "Platform / SRE: a=b + c @x"); err != nil {
		t.Fatalf("valid tag rejected: %v", err)
	}
	if err := CheckTag("", "v"); err == nil {
		t.Fatal("empty key accepted")
	}
	if err := CheckTag("k", "aws:x"); err == nil {
		t.Fatal("reserved value accepted")
	}
	var tagErr *TagError
	if err := CheckTag("k", "bad#v"); !errors.As(err, &tagErr) {
		t.Fatalf("invalid value error %v is not a TagError", err)
	}
}
