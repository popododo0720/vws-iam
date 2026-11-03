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
// alias. A project holds at most MaxAccountAliases of them: creating one
// (#88) replaces the one the project had, and an AccountAliasClaim keeps
// it unique across projects, as AWS keeps it unique across accounts.
// Deleting one is #89. Seq is one more than the greatest Seq of the
// project's aliases stored when it was created, so a later create has a
// greater Seq whatever the replicas' clocks say.
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

// AccountAliasClaim reserves account alias Name for Project across every
// project. It is stored outside any project, keyed by the alias, so of
// two projects creating one alias exactly one store create succeeds.
// Claimed is when Project last wrote the claim: CreateAccountAlias writes
// the project's AccountAlias only shortly after that, so a claim older
// than the lease whose project holds no such alias is stale and another
// project may take it over. A claim holds no secret.
type AccountAliasClaim struct {
	Name    string    `json:"name"`
	Project string    `json:"project"`
	Claimed time.Time `json:"claimed"`
}

func (AccountAliasClaim) Kind() Kind    { return KindAccountAliasClaim }
func (c AccountAliasClaim) Key() string { return c.Name }

func (c AccountAliasClaim) Validate() error {
	if !ValidAccountAlias(c.Name) || !ValidProject(c.Project) || c.Claimed.IsZero() {
		return invalid("account alias claim %q", c.Name)
	}
	return nil
}
