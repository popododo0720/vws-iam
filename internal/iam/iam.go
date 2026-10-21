// Package iam holds the IAM domain types and their validation. It is pure:
// no Kubernetes, gRPC, or storage imports.
package iam

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Kind names one stored resource type.
type Kind string

// The stored kinds. Each is one CRD in the vws-iam namespace.
const (
	KindUser      Kind = "IamUser"
	KindGroup     Kind = "IamGroup"
	KindRole      Kind = "IamRole"
	KindPolicy    Kind = "IamPolicy"
	KindAccessKey Kind = "IamAccessKey"
	KindMfaDevice Kind = "IamMfaDevice"
	KindKeyIndex  Kind = "IamAccessKeyIndex"
	KindSession   Kind = "IamSession"
	KindOperation Kind = "IamOperation"
	KindReplay    Kind = "IamReplayEntry"
	KindAttempt   Kind = "IamAttemptCounter"
)

// Kinds lists every stored kind.
var Kinds = []Kind{KindUser, KindGroup, KindRole, KindPolicy, KindAccessKey, KindMfaDevice, KindKeyIndex, KindSession, KindOperation, KindReplay, KindAttempt}

// Meta is the resource envelope every API resource carries.
type Meta struct {
	UID        string            `json:"uid,omitempty"`
	Generation int64             `json:"generation,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Updated    time.Time         `json:"updated,omitzero"`
	// RequestID is the request id of the create, for replay after a crash.
	RequestID string `json:"requestId,omitempty"`
}

// Envelope returns the envelope; promoted to every resource.
func (m Meta) Envelope() Meta { return m }

// Object is a stored IAM resource. Key is unique per kind and
// case-insensitive, like AWS IAM names.
type Object interface {
	Kind() Kind
	Key() string
	Validate() error
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid")

// The hyphen is last so the class treats it as a literal.
const nameAlphabet = "A-Za-z0-9+=,.@_-"

const (
	maxNameLen       = 64
	MaxPolicyNameLen = 128
)

func namePattern(max int) string {
	return fmt.Sprintf("[%s]{1,%d}", nameAlphabet, max)
}

func ResourceNamePattern() string { return namePattern(maxNameLen) }

func PolicyNamePattern() string { return namePattern(MaxPolicyNameLen) }

var (
	nameRE       = regexp.MustCompile("^" + ResourceNamePattern() + "$")
	policyNameRE = regexp.MustCompile("^" + PolicyNamePattern() + "$")
	pathRE       = regexp.MustCompile(`^/([\x21-\x7e]{0,510}/)?$`)
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// ValidName reports whether s is an IAM name other than a managed policy name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// ValidPolicyName reports whether s is a managed policy name.
func ValidPolicyName(s string) bool { return policyNameRE.MatchString(s) }

func checkPath(what, path string) error {
	if path != "" && !pathRE.MatchString(path) {
		return invalid("%s path %q", what, path)
	}
	return nil
}

func checkName(what, name, path string) error {
	if !ValidName(name) {
		return invalid("%s name %q", what, name)
	}
	return checkPath(what, path)
}

func checkPolicyName(name, path string) error {
	if !ValidPolicyName(name) {
		return invalid("policy name %q", name)
	}
	return checkPath("policy", path)
}

func checkAttached(arns []string) error {
	seen := map[string]bool{}
	for _, a := range arns {
		if !strings.HasPrefix(a, "arn:vws:iam::") {
			return invalid("policy arn %q", a)
		}
		if seen[a] {
			return invalid("policy %q attached twice", a)
		}
		seen[a] = true
	}
	return nil
}

func checkInline(m map[string]string) error {
	for k := range m {
		if !ValidName(k) {
			return invalid("inline policy name %q", k)
		}
	}
	return nil
}

// User is an IAM user.
type User struct {
	Meta
	Name             string            `json:"name"`
	Path             string            `json:"path,omitempty"`
	ID               string            `json:"id"`
	Created          time.Time         `json:"created"`
	AttachedPolicies []string          `json:"attachedPolicies,omitempty"`
	InlinePolicies   map[string]string `json:"inlinePolicies,omitempty"`
	// PasswordHash is an argon2id PHC string, never a password.
	PasswordHash          string    `json:"passwordHash,omitempty"`
	PasswordResetRequired bool      `json:"passwordResetRequired,omitempty"`
	PasswordLastUsed      time.Time `json:"passwordLastUsed,omitzero"`
	// SessionsRevokedBefore is when sessions were last revoked, as read on
	// the revoking replica's clock. It is reported, not compared (#46).
	SessionsRevokedBefore time.Time `json:"sessionsRevokedBefore,omitzero"`
	// SessionsRevokeGeneration counts revocations. A session records the
	// value it read at issue; a higher stored value revokes it (#46).
	SessionsRevokeGeneration uint64 `json:"sessionsRevokeGeneration,omitempty"`
	// SessionsRevokeRequests holds the request_ids of the latest
	// revocations (at most MaxRevokeRequests), so a duplicate request
	// racing its first delivery does not bump the generation twice (#48).
	SessionsRevokeRequests []string `json:"sessionsRevokeRequests,omitempty"`
}

// MaxRevokeRequests bounds SessionsRevokeRequests.
const MaxRevokeRequests = 32

func (User) Kind() Kind    { return KindUser }
func (u User) Key() string { return u.Name }
func (u User) Validate() error {
	if err := checkName("user", u.Name, u.Path); err != nil {
		return err
	}
	if u.PasswordHash != "" && !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
		return invalid("password hash is not argon2id")
	}
	if err := checkAttached(u.AttachedPolicies); err != nil {
		return err
	}
	return checkInline(u.InlinePolicies)
}

// Group is an IAM group. Membership is stored on the user.
type Group struct {
	Meta
	Name    string    `json:"name"`
	Path    string    `json:"path,omitempty"`
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	// Members are user names of the same project.
	Members          []string          `json:"members,omitempty"`
	AttachedPolicies []string          `json:"attachedPolicies,omitempty"`
	InlinePolicies   map[string]string `json:"inlinePolicies,omitempty"`
}

func (Group) Kind() Kind    { return KindGroup }
func (g Group) Key() string { return g.Name }
func (g Group) Validate() error {
	if err := checkName("group", g.Name, g.Path); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, m := range g.Members {
		if !ValidName(m) || seen[strings.ToLower(m)] {
			return invalid("member %q", m)
		}
		seen[strings.ToLower(m)] = true
	}
	if err := checkAttached(g.AttachedPolicies); err != nil {
		return err
	}
	return checkInline(g.InlinePolicies)
}

// Session duration bounds for roles.
const (
	MinSessionDuration = 15 * time.Minute
	MaxSessionDuration = 12 * time.Hour
)

// Role is an IAM role with its trust policy.
type Role struct {
	Meta
	Name               string            `json:"name"`
	Path               string            `json:"path,omitempty"`
	ID                 string            `json:"id"`
	Created            time.Time         `json:"created"`
	AssumeRolePolicy   string            `json:"assumeRolePolicy"`
	Description        string            `json:"description,omitempty"`
	MaxSessionDuration time.Duration     `json:"maxSessionDuration,omitempty"`
	AttachedPolicies   []string          `json:"attachedPolicies,omitempty"`
	InlinePolicies     map[string]string `json:"inlinePolicies,omitempty"`
	// SessionsRevokedBefore is when sessions were last revoked, as read on
	// the revoking replica's clock. It is reported, not compared (#46).
	SessionsRevokedBefore time.Time `json:"sessionsRevokedBefore,omitzero"`
	// SessionsRevokeGeneration counts revocations. A session records the
	// value it read at issue; a higher stored value revokes it (#46).
	SessionsRevokeGeneration uint64 `json:"sessionsRevokeGeneration,omitempty"`
	// SessionsRevokeRequests holds the request_ids of the latest
	// revocations (at most MaxRevokeRequests), so a duplicate request
	// racing its first delivery does not bump the generation twice (#48).
	SessionsRevokeRequests []string `json:"sessionsRevokeRequests,omitempty"`
}

func (Role) Kind() Kind    { return KindRole }
func (r Role) Key() string { return r.Name }
func (r Role) Validate() error {
	if err := checkName("role", r.Name, r.Path); err != nil {
		return err
	}
	if r.AssumeRolePolicy == "" {
		return invalid("role %q has no trust policy", r.Name)
	}
	if d := r.MaxSessionDuration; d != 0 && (d < time.Hour || d > MaxSessionDuration) {
		return invalid("max session duration %s", d)
	}
	if err := checkAttached(r.AttachedPolicies); err != nil {
		return err
	}
	return checkInline(r.InlinePolicies)
}

// PolicyVersion is one immutable document of a managed policy.
type PolicyVersion struct {
	ID       string    `json:"id"`
	Document string    `json:"document"`
	Created  time.Time `json:"created"`
}

// MaxPolicyVersions is the AWS limit of stored versions per policy.
const MaxPolicyVersions = 5

// Policy is a customer managed policy.
type Policy struct {
	Meta
	Name           string    `json:"name"`
	Path           string    `json:"path,omitempty"`
	ID             string    `json:"id"`
	Created        time.Time `json:"created"`
	Description    string    `json:"description,omitempty"`
	DefaultVersion string    `json:"defaultVersion"`
	// NextVersion numbers the next version (v<NextVersion>); 0 means len(Versions)+1.
	NextVersion int             `json:"nextVersion,omitempty"`
	Versions    []PolicyVersion `json:"versions"`
	// Tags are the AWS customer managed policy tags. They are not envelope
	// labels: AWS tag keys and values allow characters and lengths the label
	// grammar rejects (#74, #75, #76).
	Tags map[string]string `json:"tags,omitempty"`
}

func (Policy) Kind() Kind    { return KindPolicy }
func (p Policy) Key() string { return p.Name }
func (p Policy) Validate() error {
	if err := checkPolicyName(p.Name, p.Path); err != nil {
		return err
	}
	if len(p.Versions) == 0 || len(p.Versions) > MaxPolicyVersions {
		return invalid("policy %q has %d versions", p.Name, len(p.Versions))
	}
	if len(p.Tags) > MaxPolicyTags {
		return invalid("policy %q has %d tags", p.Name, len(p.Tags))
	}
	if err := CheckTags(p.Tags); err != nil {
		return invalid("policy %q tag: %v", p.Name, err)
	}
	found := false
	seen := map[string]bool{}
	for _, v := range p.Versions {
		if seen[v.ID] || v.ID == "" {
			return invalid("policy version id %q", v.ID)
		}
		seen[v.ID] = true
		found = found || v.ID == p.DefaultVersion
	}
	if !found {
		return invalid("default version %q not stored", p.DefaultVersion)
	}
	return nil
}

// Default returns the default version's document.
func (p Policy) Default() string {
	for _, v := range p.Versions {
		if v.ID == p.DefaultVersion {
			return v.Document
		}
	}
	return ""
}

// KeyStatus is an access key's state.
type KeyStatus string

// Access key states.
const (
	KeyActive   KeyStatus = "Active"
	KeyInactive KeyStatus = "Inactive"
)

// Sealed is ciphertext under a KEK. It never holds plaintext.
type Sealed struct {
	KeyID      string `json:"keyId"`
	Ciphertext []byte `json:"ciphertext"`
}

var accessKeyRE = regexp.MustCompile(`^(AKIA|ASIA)[A-Z2-7]{16}$`)

// AccessKey is a long-term access key of a user.
type AccessKey struct {
	Meta
	ID              string    `json:"id"`
	UserName        string    `json:"userName"`
	Status          KeyStatus `json:"status"`
	Created         time.Time `json:"created"`
	LastUsed        time.Time `json:"lastUsed,omitzero"`
	LastUsedService string    `json:"lastUsedService,omitempty"`
	LastUsedRegion  string    `json:"lastUsedRegion,omitempty"`
	// Root marks the project's root credential (bootstrap only).
	Root   bool   `json:"root,omitempty"`
	Secret Sealed `json:"secret"`
}

func (AccessKey) Kind() Kind    { return KindAccessKey }
func (k AccessKey) Key() string { return k.ID }
func (k AccessKey) Validate() error {
	if !accessKeyRE.MatchString(k.ID) {
		return invalid("access key id %q", k.ID)
	}
	if k.Root != (k.UserName == "") || (!k.Root && !ValidName(k.UserName)) {
		return invalid("user name %q (root %v)", k.UserName, k.Root)
	}
	if k.Status != KeyActive && k.Status != KeyInactive {
		return invalid("status %q", k.Status)
	}
	if k.Secret.KeyID == "" || len(k.Secret.Ciphertext) == 0 {
		return invalid("access key %s has no sealed secret", k.ID)
	}
	return nil
}

// MfaDevice is a virtual TOTP device.
type MfaDevice struct {
	Meta
	Name       string    `json:"name"`
	Path       string    `json:"path,omitempty"`
	EnableTime time.Time `json:"enableTime,omitzero"`
	UserName   string    `json:"userName,omitempty"`
	Enabled    bool      `json:"enabled"`
	Created    time.Time `json:"created"`
	Seed       Sealed    `json:"seed"`
	// LastStep is the last accepted TOTP time step, the replay guard.
	LastStep int64 `json:"lastStep,omitempty"`
	// FailedAttempts counts wrong codes in a row; LockedUntil is set when
	// they reach the limit (brute-force guard).
	FailedAttempts int       `json:"failedAttempts,omitempty"`
	LockedUntil    time.Time `json:"lockedUntil,omitzero"`
	// LockedSince is when the running lockout began (the failure that
	// locked it); renewals never extend LockedUntil past
	// LockedSince+mfa.MaxLockout (#48).
	LockedSince time.Time `json:"lockedSince,omitzero"`
}

func (MfaDevice) Kind() Kind    { return KindMfaDevice }
func (d MfaDevice) Key() string { return d.Name }
func (d MfaDevice) Validate() error {
	if !ValidName(d.Name) {
		return invalid("mfa device name %q", d.Name)
	}
	if d.Enabled && d.UserName == "" {
		return invalid("enabled mfa device %q has no user", d.Name)
	}
	if d.Seed.KeyID == "" || len(d.Seed.Ciphertext) == 0 {
		return invalid("mfa device %q has no sealed seed", d.Name)
	}
	return nil
}
