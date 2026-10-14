package iam

import (
	"regexp"
	"time"
)

var projectRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ValidProject reports whether s is a project id (the account).
func ValidProject(s string) bool { return projectRE.MatchString(s) }

// KeyIndex maps a globally unique access key id to its project, so
// Authenticate can find a key from the id alone. It is not project-scoped.
type KeyIndex struct {
	ID      string `json:"id"`
	Project string `json:"project"`
}

func (KeyIndex) Kind() Kind    { return KindKeyIndex }
func (k KeyIndex) Key() string { return k.ID }
func (k KeyIndex) Validate() error {
	if !accessKeyRE.MatchString(k.ID) || !ValidProject(k.Project) {
		return invalid("key index %q -> %q", k.ID, k.Project)
	}
	return nil
}

var hashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Session is a console login session. Key is the SHA-256 hex of the
// session token; the token itself is never stored.
type Session struct {
	Hash     string    `json:"hash"`
	Project  string    `json:"project"`
	UserName string    `json:"userName,omitempty"` // empty for root
	MFA      bool      `json:"mfa,omitempty"`
	AuthTime time.Time `json:"authTime"`
	Expires  time.Time `json:"expires"`
	SourceIP string    `json:"sourceIp,omitempty"`
}

func (Session) Kind() Kind    { return KindSession }
func (s Session) Key() string { return s.Hash }
func (s Session) Validate() error {
	if !hashRE.MatchString(s.Hash) || !ValidProject(s.Project) || (s.UserName != "" && !ValidName(s.UserName)) || s.Expires.IsZero() {
		return invalid("session")
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
	if !opIDRE.MatchString(o.ID) || len(o.Response) == 0 {
		return invalid("operation %q", o.ID)
	}
	return nil
}
