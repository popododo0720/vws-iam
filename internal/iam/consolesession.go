package iam

import (
	"regexp"
	"time"
)

// consoleSessionIDRE is an AIP-122 resource id, the final segment of
// projects/{project}/consoleSessions/{id} that console-api chooses.
var consoleSessionIDRE = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ConsoleSession is a console sign-in session console-api creates and every
// console-api instance shares (vws.iam.v1 ConsoleSessionService, #454).
// console-api keeps the token and sends only its SHA-256 digest; Hash, the
// key, is the hex SHA-256 of that digest, so neither the token nor the
// digest is stored.
type ConsoleSession struct {
	Hash    string `json:"hash"`
	Project string `json:"project"`
	ID      string `json:"id"`
	// UserName is empty for the account root user.
	UserName string `json:"userName,omitempty"`
	// UserUID is the UID of the user (for root, of the root login) that
	// signed in; another UID under the same name never gets the session.
	UserUID string `json:"userUid"`
	// RevokeGeneration is the user's SessionsRevokeGeneration at create; a
	// higher stored value revokes the session.
	RevokeGeneration uint64        `json:"revokeGeneration,omitempty"`
	MFA              bool          `json:"mfa,omitempty"`
	SourceIP         string        `json:"sourceIp,omitempty"`
	Created          time.Time     `json:"created"`
	Expires          time.Time     `json:"expires"`
	IdleTimeout      time.Duration `json:"idleTimeout,omitempty"`
	LastActive       time.Time     `json:"lastActive,omitzero"`
	Revoked          time.Time     `json:"revoked,omitzero"`
}

func (ConsoleSession) Kind() Kind    { return KindConsoleSession }
func (s ConsoleSession) Key() string { return s.Hash }
func (s ConsoleSession) Validate() error {
	if !hashRE.MatchString(s.Hash) || !ValidProject(s.Project) || !consoleSessionIDRE.MatchString(s.ID) ||
		(s.UserName != "" && !ValidName(s.UserName)) || s.UserUID == "" ||
		s.Created.IsZero() || !s.Expires.After(s.Created) || s.IdleTimeout < 0 {
		return invalid("console session")
	}
	return nil
}

// ValidConsoleSessionID reports whether id is a console session resource id.
func ValidConsoleSessionID(id string) bool { return consoleSessionIDRE.MatchString(id) }
