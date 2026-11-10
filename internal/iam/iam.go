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
	KindUser       Kind = "IamUser"
	KindGroup      Kind = "IamGroup"
	KindRole       Kind = "IamRole"
	KindPolicy     Kind = "IamPolicy"
	KindAccessKey  Kind = "IamAccessKey"
	KindMfaDevice  Kind = "IamMfaDevice"
	KindKeyIndex   Kind = "IamAccessKeyIndex"
	KindSession    Kind = "IamSession"
	KindOperation  Kind = "IamOperation"
	KindReplay     Kind = "IamReplayEntry"
	KindAttempt    Kind = "IamAttemptCounter"
	KindMemberLock Kind = "IamGroupMembershipLock"
	KindFidoDevice Kind = "IamFidoDevice"
	// KindInstanceProfile is an instance profile (#97).
	KindInstanceProfile Kind = "IamInstanceProfile"
	// KindAccountAlias is an account alias (#90).
	KindAccountAlias Kind = "IamAccountAlias"
	// KindAccountAliasClaim reserves an account alias across projects (#88).
	KindAccountAliasClaim Kind = "IamAccountAliasClaim"
	// KindPasswordPolicy is the account password policy (#84).
	KindPasswordPolicy Kind = "IamAccountPasswordPolicy"
	// KindRootLogin is the root user's console password (#34).
	KindRootLogin Kind = "IamRootLogin"
	// KindSAMLProvider is a SAML identity provider (#196).
	KindSAMLProvider Kind = "IamSAMLProvider"
	// KindOIDCProvider is an OpenID Connect identity provider (#208).
	KindOIDCProvider Kind = "IamOIDCProvider"
)

// Kinds lists every stored kind.
var Kinds = []Kind{
	KindUser, KindGroup, KindRole, KindPolicy, KindAccessKey, KindMfaDevice,
	KindKeyIndex, KindSession, KindOperation, KindReplay, KindAttempt, KindMemberLock, KindFidoDevice,
	KindInstanceProfile, KindAccountAlias, KindAccountAliasClaim, KindPasswordPolicy, KindRootLogin,
	KindSAMLProvider, KindOIDCProvider,
}

// Meta is the resource envelope every API resource carries.
type Meta struct {
	UID        string            `json:"uid,omitempty"`
	Generation int64             `json:"generation,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Updated    time.Time         `json:"updated,omitzero"`
	// RequestID is the request id of the create, for replay after a crash.
	RequestID string `json:"requestId,omitempty"`
	// Requests holds the request tokens of the latest updates (at most
	// MaxRequests), each written in the compare-and-swap that applied the
	// update, so a duplicate racing its first delivery is not applied
	// again (#50).
	Requests []string `json:"requests,omitempty"`
}

// Envelope returns the envelope; promoted to every resource.
func (m Meta) Envelope() Meta { return m }

// EnvelopeRef returns the envelope for writing; promoted to every resource.
func (m *Meta) EnvelopeRef() *Meta { return m }

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
	// MaxGroupNameLen is the AWS GroupName limit; user, role, and other
	// names stay at maxNameLen (#135).
	MaxGroupNameLen = 128
	// MaxSerialNumberLen is the AWS SerialNumber limit of every call that
	// takes an MFA serial (EnableMFADevice, ResyncMFADevice,
	// GetSessionToken, AssumeRole).
	MaxSerialNumberLen = 256
	// MaxMFADeviceNameLen bounds a virtual MFA device name. AWS
	// VirtualMFADeviceName has no maximum, but its serial
	// arn:vws:iam::<project>:mfa/<name> must fit MaxSerialNumberLen, so
	// this is the longest name whose root-path serial fits in every
	// project (#179).
	MaxMFADeviceNameLen = MaxSerialNumberLen - len("arn:"+Partition+":iam::") - maxProjectLen - len(":mfa/")
)

func namePattern(max int) string {
	return fmt.Sprintf("[%s]{1,%d}", nameAlphabet, max)
}

func ResourceNamePattern() string { return namePattern(maxNameLen) }

func PolicyNamePattern() string { return namePattern(MaxPolicyNameLen) }

// GroupNamePattern is the AWS GroupName rule: 1 to MaxGroupNameLen
// characters of the IAM name alphabet.
func GroupNamePattern() string { return namePattern(MaxGroupNameLen) }

// MFADeviceNamePattern is the virtual MFA device name rule: 1 to
// MaxMFADeviceNameLen characters of the IAM name alphabet.
func MFADeviceNamePattern() string { return namePattern(MaxMFADeviceNameLen) }

var (
	nameRE       = regexp.MustCompile("^" + ResourceNamePattern() + "$")
	policyNameRE = regexp.MustCompile("^" + PolicyNamePattern() + "$")
	groupNameRE  = regexp.MustCompile("^" + GroupNamePattern() + "$")
	mfaNameRE    = regexp.MustCompile("^" + MFADeviceNamePattern() + "$")
	pathRE       = regexp.MustCompile(`^/([\x21-\x7e]{1,510}/)?$`)
)

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// ValidName reports whether s is an IAM name other than a managed policy name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// MaxRequestIDLen bounds a CreateAccessKey request_id, which is stored
// with the key it created.
const MaxRequestIDLen = 64

var requestIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidRequestID reports whether s is a request_id that can be stored with
// an access key: 1 to MaxRequestIDLen characters of [A-Za-z0-9_-], which
// covers a UUID4.
func ValidRequestID(s string) bool { return requestIDRE.MatchString(s) }

// ValidPolicyName reports whether s is a managed or inline policy name: 1 to
// 128 characters of [A-Za-z0-9+=,.@_-], the AWS PolicyName rule.
func ValidPolicyName(s string) bool { return policyNameRE.MatchString(s) }

// ValidGroupName reports whether s is a group name: 1 to 128 characters of
// [A-Za-z0-9+=,.@_-], the AWS GroupName rule.
func ValidGroupName(s string) bool { return groupNameRE.MatchString(s) }

// ValidMFADeviceName reports whether s is a virtual MFA device name: 1 to
// MaxMFADeviceNameLen characters of [A-Za-z0-9+=,.@_-].
func ValidMFADeviceName(s string) bool { return mfaNameRE.MatchString(s) }

// MaxPathPrefixLen is the AWS limit on a list call's PathPrefix.
const MaxPathPrefixLen = 512

var pathPrefixRE = regexp.MustCompile(`^/[\x21-\x7f]*$`)

// ValidPathPrefix reports whether s is a PathPrefix of an IAM list call:
// 1 to MaxPathPrefixLen characters matching the AWS pattern
// \u002F[\u0021-\u007F]*, a slash followed by printable ASCII or DEL.
func ValidPathPrefix(s string) bool {
	return len(s) <= MaxPathPrefixLen && pathPrefixRE.MatchString(s)
}

// MaxPathLen is the AWS limit on an entity's Path.
const MaxPathLen = 512

// ValidPath reports whether s is the Path of an IAM entity: 1 to
// MaxPathLen characters matching the AWS pattern
// (\u002F)|(\u002F[\u0021-\u007E]+\u002F), "/" or a slash-delimited
// run of printable ASCII.
func ValidPath(s string) bool { return pathRE.MatchString(s) }

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
		if !ValidPolicyName(k) {
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
	// FidoRegistrations counts FIDO security key registrations. Each one
	// writes it, so a DeleteUser that checked for keys before the
	// registration fails its versioned delete (#133).
	FidoRegistrations uint64 `json:"fidoRegistrations,omitempty"`
	// PermissionsBoundary is the ARN of the managed policy that is the
	// user's permissions boundary (PutUserPermissionsBoundary, #98);
	// empty when the user has none (DeleteUserPermissionsBoundary, #99).
	PermissionsBoundary string `json:"permissionsBoundary,omitempty"`
	RenameState
}

// MaxRevokeRequests bounds SessionsRevokeRequests.
const MaxRevokeRequests = 32

func (User) Kind() Kind    { return KindUser }
func (u User) Key() string { return u.Name }
func (u User) Validate() error {
	if err := u.validRequests(); err != nil {
		return err
	}
	if err := checkName("user", u.Name, u.Path); err != nil {
		return err
	}
	if err := u.check("user", u.Name, ValidName); err != nil {
		return err
	}
	if u.PasswordHash != "" && !strings.HasPrefix(u.PasswordHash, "$argon2id$") {
		return invalid("password hash is not argon2id")
	}
	if b := u.PermissionsBoundary; b != "" && !ValidPolicyARN(b) {
		return invalid("user %q permissions boundary %q is not a policy ARN", u.Name, b)
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
	RenameState
}

func (Group) Kind() Kind    { return KindGroup }
func (g Group) Key() string { return g.Name }
func (g Group) Validate() error {
	if err := g.validRequests(); err != nil {
		return err
	}
	if !ValidGroupName(g.Name) {
		return invalid("group name %q", g.Name)
	}
	if err := checkPath("group", g.Path); err != nil {
		return err
	}
	if err := g.check("group", g.Name, ValidGroupName); err != nil {
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
	// LinkedService is the service principal that owns a service-linked
	// role (CreateServiceLinkedRole, #103); empty for every other role.
	// Only DeleteServiceLinkedRole deletes a role that has one (#104).
	LinkedService string `json:"linkedService,omitempty"`
	// PermissionsBoundary is the ARN of the managed policy that is the
	// role's permissions boundary (PutRolePermissionsBoundary, #100);
	// empty when the role has none (DeleteRolePermissionsBoundary, #101).
	PermissionsBoundary string `json:"permissionsBoundary,omitempty"`
	// Tags are the AWS role tags (ListRoleTags, #73). They are not envelope
	// labels: AWS tag keys and values allow characters and lengths the label
	// grammar rejects.
	Tags map[string]string `json:"tags,omitempty"`
}

func (Role) Kind() Kind    { return KindRole }
func (r Role) Key() string { return r.Name }
func (r Role) Validate() error {
	if err := r.validRequests(); err != nil {
		return err
	}
	if err := checkName("role", r.Name, r.Path); err != nil {
		return err
	}
	if r.AssumeRolePolicy == "" {
		return invalid("role %q has no trust policy", r.Name)
	}
	if d := r.MaxSessionDuration; d != 0 && (d < time.Hour || d > MaxSessionDuration) {
		return invalid("max session duration %s", d)
	}
	if err := checkServiceLinked(r); err != nil {
		return err
	}
	if b := r.PermissionsBoundary; b != "" && !ValidPolicyARN(b) {
		return invalid("role %q permissions boundary %q is not a policy ARN", r.Name, b)
	}
	if len(r.Tags) > MaxRoleTags {
		return invalid("role %q has %d tags", r.Name, len(r.Tags))
	}
	if err := CheckTags(r.Tags); err != nil {
		return invalid("role %q tag: %v", r.Name, err)
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
	// Request is the request token of the CreatePolicyVersion that added
	// it, so a duplicate of that request answers with this version (#50).
	Request string `json:"request,omitempty"`
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
	if err := p.validRequests(); err != nil {
		return err
	}
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
		if v.Request != "" && !requestTokenRE.MatchString(v.Request) {
			return invalid("policy version %q request token %q", v.ID, v.Request)
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
	// KeyPending is a key written by CreateAccessKey but not yet committed
	// under the AccessKeysPerUser quota lock. It authenticates nothing, is
	// not listed or counted, and is removed by the next create for its user.
	KeyPending KeyStatus = "Pending"
)

// Sealed is ciphertext under a KEK. It never holds plaintext.
type Sealed struct {
	KeyID      string `json:"keyId"`
	Ciphertext []byte `json:"ciphertext"`
}

var (
	accessKeyRE     = regexp.MustCompile(`^(AKIA|ASIA)[A-Z2-7]{16}$`)
	legacyRootKeyRE = regexp.MustCompile(`^VWS[A-Z0-9]{17}$`)
)

// ValidRootAccessKeyID accepts generated AKIA ids and the legacy console-api
// VWS[A-Z0-9]{17} format. Only imported root credentials may use VWS ids;
// IAM user keys remain AKIA and temporary session keys remain ASIA.
func ValidRootAccessKeyID(id string) bool {
	return strings.HasPrefix(id, "AKIA") && accessKeyRE.MatchString(id) || legacyRootKeyRE.MatchString(id)
}

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
	Root bool `json:"root,omitempty"`
	// Reserved marks a pending key whose write was confirmed under the
	// quota lock hold. It is still pending: CreateAccessKey with a user
	// etag activates it only while the parent user is at that etag (#139).
	Reserved bool   `json:"reserved,omitempty"`
	Secret   Sealed `json:"secret"`
}

func (AccessKey) Kind() Kind    { return KindAccessKey }
func (k AccessKey) Key() string { return k.ID }
func (k AccessKey) Validate() error {
	if err := k.validRequests(); err != nil {
		return err
	}
	if !accessKeyRE.MatchString(k.ID) && (!k.Root || !legacyRootKeyRE.MatchString(k.ID)) {
		return invalid("access key id %q", k.ID)
	}
	if k.Root != (k.UserName == "") || (!k.Root && !ValidName(k.UserName)) {
		return invalid("user name %q (root %v)", k.UserName, k.Root)
	}
	if k.Status != KeyActive && k.Status != KeyInactive && k.Status != KeyPending {
		return invalid("status %q", k.Status)
	}
	if k.Reserved && k.Status != KeyPending {
		return invalid("access key %s is reserved but not pending", k.ID)
	}
	if k.Secret.KeyID == "" || len(k.Secret.Ciphertext) == 0 {
		return invalid("access key %s has no sealed secret", k.ID)
	}
	if k.RequestID != "" && (k.Root || !ValidRequestID(k.RequestID)) {
		return invalid("access key %s request id", k.ID)
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
	// Drift is the device clock minus the service clock in TOTP steps,
	// learned by ResyncMFADevice; codes are checked around now+Drift.
	Drift int64 `json:"drift,omitempty"`
	// FailedAttempts counts wrong codes in a row; LockedUntil is set when
	// they reach the limit (brute-force guard).
	FailedAttempts int       `json:"failedAttempts,omitempty"`
	LockedUntil    time.Time `json:"lockedUntil,omitzero"`
	// LockedSince is when the running lockout began (the failure that
	// locked it); renewals never extend LockedUntil past
	// LockedSince+mfa.MaxLockout (#48).
	LockedSince time.Time `json:"lockedSince,omitzero"`
	// Lockouts counts the lockouts in a row since the last accepted code;
	// each one lasts twice the one before, up to mfa.MaxLockout (#29).
	Lockouts int `json:"lockouts,omitempty"`
	// Tags are the AWS virtual MFA device tags. They are not envelope
	// labels: AWS tag keys and values allow characters and lengths the
	// label grammar rejects (#77, #78, #79).
	Tags map[string]string `json:"tags,omitempty"`
}

func (MfaDevice) Kind() Kind    { return KindMfaDevice }
func (d MfaDevice) Key() string { return d.Name }
func (d MfaDevice) Validate() error {
	if err := d.validRequests(); err != nil {
		return err
	}
	if !ValidMFADeviceName(d.Name) {
		return invalid("mfa device name %q", d.Name)
	}
	if err := checkPath("mfa device", d.Path); err != nil {
		return err
	}
	if d.Enabled && d.UserName == "" {
		return invalid("enabled mfa device %q has no user", d.Name)
	}
	if d.Seed.KeyID == "" || len(d.Seed.Ciphertext) == 0 {
		return invalid("mfa device %q has no sealed seed", d.Name)
	}
	if d.FailedAttempts < 0 || d.Lockouts < 0 {
		return invalid("mfa device %q has a negative lockout counter", d.Name)
	}
	if len(d.Tags) > MaxMFADeviceTags {
		return invalid("mfa device %q has %d tags", d.Name, len(d.Tags))
	}
	if err := CheckTags(d.Tags); err != nil {
		return invalid("mfa device %q tag: %v", d.Name, err)
	}
	return nil
}
