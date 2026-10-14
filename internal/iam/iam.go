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
)

// Kinds lists every stored kind.
var Kinds = []Kind{KindUser, KindGroup, KindRole, KindPolicy, KindAccessKey, KindMfaDevice}

// Object is a stored IAM resource. Key is unique per kind and
// case-insensitive, like AWS IAM names.
type Object interface {
	Kind() Kind
	Key() string
	Validate() error
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid")

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	pathRE = regexp.MustCompile(`^/([\x21-\x7e]{0,510}/)?$`)
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// ValidName reports whether s is an IAM user, group, role, or policy name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

func checkName(what, name, path string) error {
	if !ValidName(name) {
		return invalid("%s name %q", what, name)
	}
	if path != "" && !pathRE.MatchString(path) {
		return invalid("%s path %q", what, path)
	}
	return nil
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
	Name             string            `json:"name"`
	Path             string            `json:"path,omitempty"`
	ID               string            `json:"id"`
	Created          time.Time         `json:"created"`
	Groups           []string          `json:"groups,omitempty"`
	AttachedPolicies []string          `json:"attachedPolicies,omitempty"`
	InlinePolicies   map[string]string `json:"inlinePolicies,omitempty"`
	// PasswordHash is an argon2id PHC string, never a password.
	PasswordHash string `json:"passwordHash,omitempty"`
}

func (User) Kind() Kind    { return KindUser }
func (u User) Key() string { return u.Name }
func (u User) Validate() error {
	if err := checkName("user", u.Name, u.Path); err != nil {
		return err
	}
	for _, g := range u.Groups {
		if !ValidName(g) {
			return invalid("group name %q", g)
		}
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
	Name             string            `json:"name"`
	Path             string            `json:"path,omitempty"`
	ID               string            `json:"id"`
	Created          time.Time         `json:"created"`
	AttachedPolicies []string          `json:"attachedPolicies,omitempty"`
	InlinePolicies   map[string]string `json:"inlinePolicies,omitempty"`
}

func (Group) Kind() Kind    { return KindGroup }
func (g Group) Key() string { return g.Name }
func (g Group) Validate() error {
	if err := checkName("group", g.Name, g.Path); err != nil {
		return err
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
	Name               string            `json:"name"`
	Path               string            `json:"path,omitempty"`
	ID                 string            `json:"id"`
	Created            time.Time         `json:"created"`
	AssumeRolePolicy   string            `json:"assumeRolePolicy"`
	MaxSessionDuration time.Duration     `json:"maxSessionDuration,omitempty"`
	AttachedPolicies   []string          `json:"attachedPolicies,omitempty"`
	InlinePolicies     map[string]string `json:"inlinePolicies,omitempty"`
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
	Name           string          `json:"name"`
	Path           string          `json:"path,omitempty"`
	ID             string          `json:"id"`
	Created        time.Time       `json:"created"`
	DefaultVersion string          `json:"defaultVersion"`
	Versions       []PolicyVersion `json:"versions"`
}

func (Policy) Kind() Kind    { return KindPolicy }
func (p Policy) Key() string { return p.Name }
func (p Policy) Validate() error {
	if err := checkName("policy", p.Name, p.Path); err != nil {
		return err
	}
	if len(p.Versions) == 0 || len(p.Versions) > MaxPolicyVersions {
		return invalid("policy %q has %d versions", p.Name, len(p.Versions))
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
	ID       string    `json:"id"`
	UserName string    `json:"userName"`
	Status   KeyStatus `json:"status"`
	Created  time.Time `json:"created"`
	LastUsed time.Time `json:"lastUsed,omitzero"`
	Secret   Sealed    `json:"secret"`
}

func (AccessKey) Kind() Kind    { return KindAccessKey }
func (k AccessKey) Key() string { return k.ID }
func (k AccessKey) Validate() error {
	if !accessKeyRE.MatchString(k.ID) {
		return invalid("access key id %q", k.ID)
	}
	if !ValidName(k.UserName) {
		return invalid("user name %q", k.UserName)
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
	Name     string    `json:"name"`
	UserName string    `json:"userName,omitempty"`
	Enabled  bool      `json:"enabled"`
	Created  time.Time `json:"created"`
	Seed     Sealed    `json:"seed"`
	// LastStep is the last accepted TOTP time step, the replay guard.
	LastStep int64 `json:"lastStep,omitempty"`
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
