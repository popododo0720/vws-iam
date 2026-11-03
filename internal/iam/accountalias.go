package iam

import "time"

// Account alias limits. AWS bounds AccountAlias to 3 to 63 characters
// and an account to one alias (a fixed quota).
const (
	MinAccountAliasLen = 3
	MaxAccountAliasLen = 63
	MaxAccountAliases  = 1
)

// ValidAccountAlias reports whether s is an account alias: 3 to 63
// lowercase letters, digits and hyphens that neither starts nor ends with
// a hyphen nor holds two in a row, the AWS AccountAlias rule
// ^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$ (Go regexp has no lookahead,
// so it is checked by hand).
func ValidAccountAlias(s string) bool {
	if len(s) < MinAccountAliasLen || len(s) > MaxAccountAliasLen {
		return false
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-':
			if s[i-1] == '-' {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// AccountAlias is the alias of an account (a VWS project), keyed by the
// alias. A project holds at most MaxAccountAliases of them: a create
// (#88) replaces the previous one, ordered by Seq (no clocks), and an
// AccountAliasClaim keeps it unique across projects; deleting is #89.
type AccountAlias struct {
	Meta
	Name    string    `json:"name"`
	Created time.Time `json:"created"`
	Seq     int64     `json:"seq,omitempty"`
}

func (AccountAlias) Kind() Kind    { return KindAccountAlias }
func (a AccountAlias) Key() string { return a.Name }

func (a AccountAlias) Validate() error {
	if !ValidAccountAlias(a.Name) {
		return invalid("account alias %q", a.Name)
	}
	return nil
}

// AccountAliasClaim points account alias Name, across every project, at
// the one stored AccountAlias of Project with UID: a project holds an
// alias only while its claim points at it. It is stored outside any
// project, keyed by the alias, and never deleted; CreateAccountAlias
// writes it by compare-and-swap, and repoints it only when it no longer
// points at a stored alias. A claim holds no secret.
type AccountAliasClaim struct {
	Name    string `json:"name"`
	Project string `json:"project"`
	UID     string `json:"uid"`
}

func (AccountAliasClaim) Kind() Kind    { return KindAccountAliasClaim }
func (c AccountAliasClaim) Key() string { return c.Name }

func (c AccountAliasClaim) Validate() error {
	if !ValidAccountAlias(c.Name) || !ValidProject(c.Project) || c.UID == "" {
		return invalid("account alias claim %q", c.Name)
	}
	return nil
}
