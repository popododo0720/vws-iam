package iam

import (
	"regexp"
	"time"
)

// Instance profile limits. AWS bounds InstanceProfileName to 1 to 128
// characters of [\w+=,.@-] and an instance profile to one role (a fixed
// quota).
const (
	MaxInstanceProfileNameLen = 128
	MaxInstanceProfileRoles   = 1
)

// InstanceProfileNamePattern is the AWS InstanceProfileName rule: 1 to
// MaxInstanceProfileNameLen characters of the IAM name alphabet.
func InstanceProfileNamePattern() string { return namePattern(MaxInstanceProfileNameLen) }

var instanceProfileNameRE = regexp.MustCompile("^" + InstanceProfileNamePattern() + "$")

// ValidInstanceProfileName reports whether s is an instance profile name:
// 1 to 128 characters of [A-Za-z0-9+=,.@_-], the AWS InstanceProfileName
// rule.
func ValidInstanceProfileName(s string) bool { return instanceProfileNameRE.MatchString(s) }

// InstanceProfile is an IAM instance profile: a container for at most one
// role that an instance can assume. Roles holds the names of its roles as
// stored, at most MaxInstanceProfileRoles of them.
type InstanceProfile struct {
	Meta
	Name    string    `json:"name"`
	Path    string    `json:"path,omitempty"`
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	Roles   []string  `json:"roles,omitempty"`
}

func (InstanceProfile) Kind() Kind    { return KindInstanceProfile }
func (p InstanceProfile) Key() string { return p.Name }

func (p InstanceProfile) Validate() error {
	if !ValidInstanceProfileName(p.Name) {
		return invalid("instance profile name %q", p.Name)
	}
	if err := checkPath("instance profile", p.Path); err != nil {
		return err
	}
	if len(p.Roles) > MaxInstanceProfileRoles {
		return invalid("instance profile %q has %d roles, at most %d", p.Name, len(p.Roles), MaxInstanceProfileRoles)
	}
	for _, r := range p.Roles {
		if !ValidName(r) {
			return invalid("instance profile %q role name %q", p.Name, r)
		}
	}
	return nil
}
