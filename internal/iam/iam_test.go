package iam_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

func TestValidateRejectsHostileInput(t *testing.T) {
	seal := iam.Sealed{KeyID: "k", Ciphertext: []byte{1}}
	bad := []iam.Object{
		iam.User{Name: ""},
		iam.User{Name: strings.Repeat("a", 65)},
		iam.User{Name: "a/b"},
		iam.User{Name: "a", Path: "no-slash"},
		iam.User{Name: "a", PasswordHash: "plaintext"},
		iam.User{Name: "a", AttachedPolicies: []string{"arn:aws:iam::1:policy/x"}},
		iam.Group{Name: "g", AttachedPolicies: []string{"arn:vws:iam::1:policy/x", "arn:vws:iam::1:policy/x"}},
		iam.Role{Name: "r"},
		iam.Role{Name: "r", AssumeRolePolicy: "{}", MaxSessionDuration: 13 * time.Hour},
		iam.Policy{Name: "p"},
		iam.Policy{Name: "p", DefaultVersion: "v2", Versions: []iam.PolicyVersion{{ID: "v1"}}},
		iam.AccessKey{ID: "short", UserName: "a", Status: iam.KeyActive, Secret: seal},
		iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", UserName: "a", Status: "On", Secret: seal},
		iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", UserName: "a", Status: iam.KeyActive},
		withRequestID(iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", UserName: "a", Status: iam.KeyActive, Secret: seal}, "a b"),
		withRequestID(iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", UserName: "a", Status: iam.KeyActive, Secret: seal},
			strings.Repeat("a", 65)),
		withRequestID(iam.AccessKey{ID: "AKIAABCDEFGHIJKLMNOP", Root: true, Status: iam.KeyActive, Secret: seal}, "r"),
		iam.MfaDevice{Name: "d", Enabled: true, Seed: seal},
		iam.MfaDevice{Name: "d"},
		iam.MfaDevice{Name: "d", Path: "team", Seed: seal},
	}
	for i, o := range bad {
		if err := o.Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("%d %T: %v, want ErrInvalid", i, o, err)
		}
	}
}

func withRequestID(k iam.AccessKey, id string) iam.AccessKey {
	k.RequestID = id
	return k
}

// TestValidRequestID: a CreateAccessKey request_id is 1 to 64 characters
// of [A-Za-z0-9_-] (#137).
func TestValidRequestID(t *testing.T) {
	good := []string{"6f1c2b9e-4d3a-4b8e-9a7f-2c5d1e0f3a4b", "a", "A_z-9", strings.Repeat("a", iam.MaxRequestIDLen)}
	for _, s := range good {
		if !iam.ValidRequestID(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", strings.Repeat("a", iam.MaxRequestIDLen+1), "a b", "a/b", "a;b", "a\nb", "\u00e9"} {
		if iam.ValidRequestID(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestSplitUserARN(t *testing.T) {
	for _, tc := range []struct {
		arn, account, path, name string
	}{
		{"arn:vws:iam::proj-a:user/alice", "proj-a", "/", "alice"},
		{"arn:vws:iam::proj-a:user/allowed/team/alice", "proj-a", "/allowed/team/", "alice"},
	} {
		account, path, name, ok := iam.SplitUserARN(tc.arn)
		if !ok || account != tc.account || path != tc.path || name != tc.name {
			t.Errorf("SplitUserARN(%q) = %q %q %q %v", tc.arn, account, path, name, ok)
		}
		if got := iam.UserARN(account, iam.User{Name: name, Path: path}); got != tc.arn {
			t.Errorf("round trip %q: %q", tc.arn, got)
		}
	}
	for _, arn := range []string{
		"", "alice", "projects/proj-a/users/alice",
		"arn:aws:iam::proj-a:user/alice",
		"arn:vws:iam::proj-a:role/alice",
		"arn:vws:iam:::user/alice",
		"arn:vws:iam::Bad_Project:user/alice",
		"arn:vws:iam::proj-a:user/",
		"arn:vws:iam::proj-a:user/allowed/",
		"arn:vws:iam::proj-a:user/a b",
		"arn:vws:iam::proj-a:user/allowed path/alice",
	} {
		if a, p, n, ok := iam.SplitUserARN(arn); ok {
			t.Errorf("SplitUserARN(%q) accepted: %q %q %q", arn, a, p, n)
		}
	}
}

func TestARNs(t *testing.T) {
	if got := iam.UserARN("000000000000", iam.User{Name: "a", Path: "/dev/"}); got != "arn:vws:iam::000000000000:user/dev/a" {
		t.Fatal(got)
	}
	if got := iam.RoleARN("000000000000", iam.Role{Name: "r"}); got != "arn:vws:iam::000000000000:role/r" {
		t.Fatal(got)
	}
	got := iam.MfaDeviceARN("000000000000", iam.MfaDevice{Name: "d", Path: "/team/"})
	if want := "arn:vws:iam::000000000000:mfa/team/d"; got != want {
		t.Fatal(got)
	}
	if got := iam.MfaDeviceARN("000000000000", iam.MfaDevice{Name: "d"}); got != "arn:vws:iam::000000000000:mfa/d" {
		t.Fatal(got)
	}
	name, path, ok := iam.SplitMfaDeviceARN("000000000000", "arn:vws:iam::000000000000:mfa/team/d")
	if !ok || name != "d" || path != "/team/" {
		t.Fatalf("split path serial: %q %q %v", name, path, ok)
	}
	name, path, ok = iam.SplitMfaDeviceARN("000000000000", "arn:vws:iam::000000000000:mfa/d")
	if !ok || name != "d" || path != "/" {
		t.Fatalf("split root serial: %q %q %v", name, path, ok)
	}
	if _, _, ok := iam.SplitMfaDeviceARN("000000000000", "arn:vws:iam::111111111111:mfa/d"); ok {
		t.Fatal("split accepted another account")
	}
}

func TestPolicyNameLength(t *testing.T) {
	policy := func(name string) iam.Policy {
		return iam.Policy{Name: name, DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1"}}}
	}
	for _, name := range []string{"a", strings.Repeat("a", 64), strings.Repeat("a", 65), strings.Repeat("a", 128), "A.z+9=,_@-"} {
		if err := policy(name).Validate(); err != nil {
			t.Errorf("%d-character policy: %v", len(name), err)
		}
	}
	a129 := strings.Repeat("a", 129)
	err := policy(a129).Validate()
	want := `invalid: policy name "` + a129 + `"`
	if err == nil || err.Error() != want || !errors.Is(err, iam.ErrInvalid) {
		t.Errorf("129-character policy: %v", err)
	}
	for _, name := range []string{"", "bad name", "a/b"} {
		err := policy(name).Validate()
		want := `invalid: policy name "` + name + `"`
		if err == nil || err.Error() != want {
			t.Errorf("policy %q: %v, want %s", name, err, want)
		}
	}
	if err := policy(strings.Repeat("é", 64)).Validate(); !errors.Is(err, iam.ErrInvalid) {
		t.Errorf("non-ASCII policy: %v", err)
	}
	err = policy(strings.Repeat("a", 1<<20)).Validate()
	if !errors.Is(err, iam.ErrInvalid) {
		t.Errorf("1 MiB policy: nil=%v", err == nil)
	}
}

// TestInlinePolicyNameLength checks the AWS PutUserPolicy, PutGroupPolicy and
// PutRolePolicy PolicyName rule: 1 to 128 characters of [\w+=,.@-].
func TestInlinePolicyNameLength(t *testing.T) {
	trust := `{"Version":"2012-10-17","Statement":[]}`
	owners := []struct {
		kind string
		with func(inline map[string]string) iam.Object
	}{
		{"user", func(m map[string]string) iam.Object { return iam.User{Name: "user", InlinePolicies: m} }},
		{"group", func(m map[string]string) iam.Object { return iam.Group{Name: "group", InlinePolicies: m} }},
		{"role", func(m map[string]string) iam.Object {
			return iam.Role{Name: "role", AssumeRolePolicy: trust, MaxSessionDuration: time.Hour, InlinePolicies: m}
		}},
	}
	for _, o := range owners {
		ok := []string{"a", strings.Repeat("a", 64), strings.Repeat("a", 65), strings.Repeat("a", 128), "A.z+9=,_@-"}
		for _, name := range ok {
			if err := o.with(map[string]string{name: "{}"}).Validate(); err != nil {
				t.Errorf("%s inline policy of %d characters: %v", o.kind, len(name), err)
			}
		}
		for _, name := range []string{strings.Repeat("a", 129), "", "bad name", "a/b", "a:b", strings.Repeat("\u00e9", 4)} {
			err := o.with(map[string]string{name: "{}"}).Validate()
			want := `invalid: inline policy name "` + name + `"`
			if err == nil || err.Error() != want || !errors.Is(err, iam.ErrInvalid) {
				t.Errorf("%s inline policy %q: %v, want %s", o.kind, name, err, want)
			}
		}
	}
}

func TestOtherNamesStayAt64(t *testing.T) {
	n64 := strings.Repeat("n", 64)
	n65 := strings.Repeat("n", 65)
	seal := iam.Sealed{KeyID: "kek-1", Ciphertext: []byte{1, 2, 3}}
	trust := `{"Version":"2012-10-17","Statement":[]}`
	expires := time.Date(2026, 10, 14, 1, 0, 0, 0, time.UTC)
	hash := strings.Repeat("ab", 32)
	keyID := "AKIAABCDEFGHIJKLMNOP"
	cases := []struct {
		name string
		ok   iam.Object
		bad  iam.Object
	}{
		{"user", iam.User{Name: n64}, iam.User{Name: n65}},
		{"group", iam.Group{Name: n64}, iam.Group{Name: n65}},
		{
			"role",
			iam.Role{Name: n64, AssumeRolePolicy: trust, MaxSessionDuration: time.Hour},
			iam.Role{Name: n65, AssumeRolePolicy: trust, MaxSessionDuration: time.Hour},
		},
		{"mfa device", iam.MfaDevice{Name: n64, Seed: seal}, iam.MfaDevice{Name: n65, Seed: seal}},
		{
			"access key",
			iam.AccessKey{ID: keyID, UserName: n64, Status: iam.KeyActive, Secret: seal},
			iam.AccessKey{ID: keyID, UserName: n65, Status: iam.KeyActive, Secret: seal},
		},
		{
			"session",
			iam.Session{Hash: hash, Project: "proj-a", UserName: n64, Expires: expires},
			iam.Session{Hash: hash, Project: "proj-a", UserName: n65, Expires: expires},
		},
		{
			"group member",
			iam.Group{Name: "group", Members: []string{n64}},
			iam.Group{Name: "group", Members: []string{n65}},
		},
	}
	for _, tc := range cases {
		if err := tc.ok.Validate(); err != nil {
			t.Errorf("%s of 64: %v", tc.name, err)
		}
		if err := tc.bad.Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("%s of 65: %v", tc.name, err)
		}
	}
}
