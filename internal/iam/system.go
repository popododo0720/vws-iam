package iam

import (
	"regexp"
	"strings"
	"time"
)

// maxProjectLen is the longest project id projectRE matches.
const maxProjectLen = 63

var projectRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidProject reports whether s is a project id (the account).
func ValidProject(s string) bool { return projectRE.MatchString(s) }

// KeyIndex maps a globally unique access key id to its project, so
// Authenticate can find a key from the id alone. It is not project-scoped.
//
// Expires is set only on the entry of a temporary (ASIA) key of an STS
// session (#188), which is not stored itself: the entry is the only record
// of the key, kept so GetAccessKeyInfo can name its project, and is
// garbage-collected after Expires. A long-term key's entry has none.
type KeyIndex struct {
	ID      string    `json:"id"`
	Project string    `json:"project"`
	Expires time.Time `json:"expires,omitzero"`
}

// Session reports whether k is the entry of an STS session key.
func (k KeyIndex) Session() bool { return !k.Expires.IsZero() }

func (KeyIndex) Kind() Kind    { return KindKeyIndex }
func (k KeyIndex) Key() string { return k.ID }
func (k KeyIndex) Validate() error {
	switch {
	case !accessKeyRE.MatchString(k.ID) && !legacyRootKeyRE.MatchString(k.ID):
		return invalid("key index id %q", k.ID)
	case !ValidProject(k.Project):
		return invalid("key index %q project %q", k.ID, k.Project)
	case k.Session() && !strings.HasPrefix(k.ID, "ASIA"):
		return invalid("key index %q is a session entry without an ASIA key id", k.ID)
	}
	return nil
}

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Session is a console login session. Key is the SHA-256 hex of the
// session token; the token itself is never stored.
type Session struct {
	Hash     string `json:"hash"`
	Project  string `json:"project"`
	UserName string `json:"userName,omitempty"` // empty for root
	// UserUID is the UID of the user that signed in (#134); empty in a
	// session stored before it existed.
	UserUID  string    `json:"userUid,omitempty"`
	MFA      bool      `json:"mfa,omitempty"`
	AuthTime time.Time `json:"authTime"`
	Expires  time.Time `json:"expires"`
	SourceIP string    `json:"sourceIp,omitempty"`
}

// Root reports whether the session is the account root user's (#34).
func (s Session) Root() bool { return s.UserName == "" }

func (Session) Kind() Kind    { return KindSession }
func (s Session) Key() string { return s.Hash }
func (s Session) Validate() error {
	switch {
	case !hashRE.MatchString(s.Hash):
		return invalid("session hash is not SHA-256 hex")
	case !ValidProject(s.Project):
		return invalid("session project %q", s.Project)
	case s.UserName != "" && !ValidName(s.UserName):
		return invalid("session user name %q", s.UserName)
	case s.Expires.IsZero():
		return invalid("session has no expiry")
	}
	return nil
}

// Operation records a finished mutation for GetOperation and request_id
// replay. It never holds secret material: secret-bearing RPCs are not
// operations.
type Operation struct {
	ID          string `json:"id"`
	Project     string `json:"project"`
	RequestID   string `json:"requestId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	// Response is the serialized google.longrunning.Operation.
	Response []byte    `json:"response"`
	Created  time.Time `json:"created"`
}

var opIDRE = regexp.MustCompile(`^[a-z0-9-]{1,80}$`)

func (Operation) Kind() Kind    { return KindOperation }
func (o Operation) Key() string { return o.ID }
func (o Operation) Validate() error {
	if !opIDRE.MatchString(o.ID) {
		return invalid("operation id %q", o.ID)
	}
	if len(o.Response) == 0 {
		return invalid("operation %q has no response", o.ID)
	}
	return nil
}

// ReplayEntry records that a forwarded SigV4 request was used for STS, so
// every replica refuses it a second time. Key is the hex HMAC-SHA256 of
// the access key id and signature under a key derived from a KEK (one
// entry per KEK), so a store reader without the KEK cannot test guesses;
// neither is stored. Expires is when the
// entry may be garbage-collected: after it, X-Amz-Date is out of window.
type ReplayEntry struct {
	Hash    string    `json:"hash"`
	Expires time.Time `json:"expires"`
}

func (ReplayEntry) Kind() Kind    { return KindReplay }
func (r ReplayEntry) Key() string { return r.Hash }
func (r ReplayEntry) Validate() error {
	if !hashRE.MatchString(r.Hash) {
		return invalid("replay entry hash is not SHA-256 hex")
	}
	if r.Expires.IsZero() {
		return invalid("replay entry has no expiry")
	}
	return nil
}

// Attempt counter scopes: who failed authentication attempts are counted
// for, besides the per-device MFA lockout.
const (
	AttemptUser = "user"
	AttemptKey  = "key"
	AttemptIP   = "ip"
)

// AttemptCounter counts failed Login, MFA and STS-MFA attempts of one
// caller (a user, an access key or a source IP) in a fixed window, shared
// by every replica. Key is the hex HMAC-SHA256 of the scope and the
// caller under a key derived from a KEK (one counter per KEK), so a store
// reader without the KEK cannot test guesses; the user name, key id and
// IP are not stored.
type AttemptCounter struct {
	Hash        string    `json:"hash"`
	Scope       string    `json:"scope"`
	Failures    int       `json:"failures"`
	WindowStart time.Time `json:"windowStart"`
	LockedUntil time.Time `json:"lockedUntil,omitzero"`
}

func (AttemptCounter) Kind() Kind    { return KindAttempt }
func (a AttemptCounter) Key() string { return a.Hash }
func (a AttemptCounter) Validate() error {
	switch a.Scope {
	case AttemptUser, AttemptKey, AttemptIP:
	default:
		return invalid("attempt counter scope %q", a.Scope)
	}
	switch {
	case !hashRE.MatchString(a.Hash):
		return invalid("attempt counter hash is not SHA-256 hex")
	case a.Failures < 0:
		return invalid("attempt counter failures %d", a.Failures)
	case a.WindowStart.IsZero():
		return invalid("attempt counter has no window start")
	}
	return nil
}

// MaxGroupsPerUser is the AWS GroupsPerUser quota: a user is a member of
// at most this many groups (#136).
const MaxGroupsPerUser = 10

// MembershipLockKey is the key of a project's MembershipLock.
const MembershipLockKey = "group-membership"

// MembershipLock serializes the group writes of one project that add a
// member, so the GroupsPerUser quota is checked atomically with the write.
// A writer takes the lock (Holder, until Expires) by a compare-and-swap
// that also bumps Epoch, counts the groups of each new member, and commits
// the group only while the lock is still at the version it wrote. Safety
// rests on that conditional commit alone: if the lease runs out and
// another writer takes the lock, the commit fails. The lease only keeps
// writers from invalidating each other; a crashed holder blocks adds until
// Expires. It holds no user data.
type MembershipLock struct {
	Name    string    `json:"name"`
	Epoch   uint64    `json:"epoch"`
	Holder  string    `json:"holder,omitempty"`
	Expires time.Time `json:"expires,omitzero"`
}

func (MembershipLock) Kind() Kind    { return KindMemberLock }
func (l MembershipLock) Key() string { return l.Name }
func (l MembershipLock) Validate() error {
	switch {
	case l.Name != MembershipLockKey:
		return invalid("membership lock name %q", l.Name)
	case l.Holder == "":
		return nil
	case !hashRE.MatchString(l.Holder):
		return invalid("membership lock holder is not SHA-256 hex")
	case l.Expires.IsZero():
		return invalid("membership lock holder has no expiry")
	}
	return nil
}

// MaxMFADevicesPerUser is the shared AWS quota for virtual and FIDO devices.
const MaxMFADevicesPerUser = 8

// MFARegistrationLease is a per-user quota hold. Its versioned user write
// fences a device commit if another replica takes an expired hold.
type MFARegistrationLease struct {
	Holder  string    `json:"holder,omitempty"`
	Expires time.Time `json:"expires,omitzero"`
}
