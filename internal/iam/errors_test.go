package iam_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// TestValidationErrorsNameKindAndField: a validation failure names the
// object kind, its key and the field, still wraps ErrInvalid, and never
// echoes a password hash or a stored hash (#303).
func TestValidationErrorsNameKindAndField(t *testing.T) {
	const (
		key  = "AKIAABCDEFGHIJKLMNOP"
		arn  = "arn:vws:iam::p:policy/x"
		hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	seal := iam.Sealed{KeyID: "k", Ciphertext: []byte{1}}
	now := time.Unix(1, 0)
	user := func(m iam.Meta) iam.User { return iam.User{Meta: m, Name: "alice"} }
	cases := []struct {
		obj    iam.Object
		want   string
		secret string
	}{
		{
			iam.User{Name: "alice", PasswordHash: "plain-Secret1"},
			`user "alice" password hash is not argon2id`, "plain-Secret1",
		},
		{
			iam.User{Name: "alice", AttachedPolicies: []string{"arn:aws:x"}},
			`user "alice" attached policy arn "arn:aws:x"`, "",
		},
		{
			iam.Group{Name: "devs", AttachedPolicies: []string{arn, arn}},
			`group "devs" attached policy "` + arn + `" twice`, "",
		},
		{
			iam.Role{Name: "r", AssumeRolePolicy: "{}", InlinePolicies: map[string]string{"a b": ""}},
			`role "r" inline policy name "a b"`, "",
		},
		{user(iam.Meta{Requests: []string{"a b"}}), `user "alice" request token "a b"`, ""},
		{user(iam.Meta{Requests: make([]string, iam.MaxRequests+1)}), `user "alice" has 33 request tokens, at most 32`, ""},
		{
			iam.Policy{Name: "p", DefaultVersion: "v2", Versions: []iam.PolicyVersion{{ID: "v1"}}},
			`policy "p" default version "v2" not stored`, "",
		},
		{
			iam.Policy{Name: "p", DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1"}, {ID: "v1"}}},
			`policy "p" version id "v1"`, "",
		},
		{
			iam.Policy{Name: "p", DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1", Request: "a b"}}},
			`policy "p" version "v1" request token "a b"`, "",
		},
		{
			iam.AccessKey{ID: key, Status: iam.KeyActive, Secret: seal},
			`access key "` + key + `" user name "" (root false)`, "",
		},
		{
			iam.AccessKey{ID: key, UserName: "alice", Status: "On", Secret: seal},
			`access key "` + key + `" status "On"`, "",
		},
		{iam.KeyIndex{ID: "short", Project: "p"}, `key index id "short"`, ""},
		{iam.KeyIndex{ID: key, Project: "Bad_Project"}, `key index "` + key + `" project "Bad_Project"`, ""},
		{
			iam.KeyIndex{ID: key, Project: "p", Expires: now},
			`key index "` + key + `" is a session entry without an ASIA key id`, "",
		},
		{
			iam.Session{Hash: "not-a-hash-secret", Project: "p", Expires: now},
			"session hash is not SHA-256 hex", "not-a-hash-secret",
		},
		{iam.Session{Hash: hash, Project: "Bad_Project", Expires: now}, `session project "Bad_Project"`, hash},
		{iam.Session{Hash: hash, Project: "p", UserName: "a b", Expires: now}, `session user name "a b"`, hash},
		{iam.Session{Hash: hash, Project: "p"}, "session has no expiry", hash},
		{iam.Operation{ID: "Bad ID", Response: []byte{1}}, `operation id "Bad ID"`, ""},
		{iam.Operation{ID: "op-1"}, `operation "op-1" has no response`, ""},
		{
			iam.ReplayEntry{Hash: "not-a-hash-secret", Expires: now},
			"replay entry hash is not SHA-256 hex", "not-a-hash-secret",
		},
		{iam.ReplayEntry{Hash: hash}, "replay entry has no expiry", hash},
		{
			iam.AttemptCounter{Hash: "not-a-hash-secret", Scope: iam.AttemptUser, WindowStart: now},
			"attempt counter hash is not SHA-256 hex", "not-a-hash-secret",
		},
		{
			iam.AttemptCounter{Hash: hash, Scope: iam.AttemptUser, Failures: -1, WindowStart: now},
			"attempt counter failures -1", hash,
		},
		{iam.AttemptCounter{Hash: hash, Scope: iam.AttemptUser}, "attempt counter has no window start", hash},
		{iam.MembershipLock{Name: "other"}, `membership lock name "other"`, ""},
		{
			iam.MembershipLock{Name: iam.MembershipLockKey, Holder: "not-a-hash-secret"},
			"membership lock holder is not SHA-256 hex", "not-a-hash-secret",
		},
		{iam.MembershipLock{Name: iam.MembershipLockKey, Holder: hash}, "membership lock holder has no expiry", hash},
	}
	for _, c := range cases {
		err := c.obj.Validate()
		if !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("%T: %v, want ErrInvalid", c.obj, err)
			continue
		}
		if want := "invalid: " + c.want; err.Error() != want {
			t.Errorf("%T: %q, want %q", c.obj, err, want)
		}
		if c.secret != "" && strings.Contains(err.Error(), c.secret) {
			t.Errorf("%T: %q carries %q", c.obj, err, c.secret)
		}
	}
}
