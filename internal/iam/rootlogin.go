package iam

import (
	"strings"
	"time"
)

// RootLoginKey is the key of the one root login a project stores.
const RootLoginKey = "root"

// RootUserName is the LoginRequest user name of the account root user
// (vws-proto auth.proto).
const RootUserName = "root"

// RootLogin is the console sign-in of a project's root user (#34): the
// argon2id hash of its password, written by the bootstrap Job. No stored
// root login means the root user cannot sign in to the console. Meta.UID
// is new on every password change, and a root console session is bound
// to it, so a new password ends every earlier root session.
type RootLogin struct {
	Meta
	// PasswordHash is an argon2id PHC string, never a password.
	PasswordHash string    `json:"passwordHash"`
	Changed      time.Time `json:"changed"`
}

func (RootLogin) Kind() Kind  { return KindRootLogin }
func (RootLogin) Key() string { return RootLoginKey }

// Validate refuses a root login without a UID or an argon2id hash.
func (r RootLogin) Validate() error {
	if r.UID == "" {
		return invalid("root login without a uid")
	}
	if !strings.HasPrefix(r.PasswordHash, "$argon2id$") {
		return invalid("root password hash is not argon2id")
	}
	return nil
}
