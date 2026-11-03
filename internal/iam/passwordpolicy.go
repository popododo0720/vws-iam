package iam

// Account password policy limits, from the AWS
// UpdateAccountPasswordPolicy parameters.
const (
	MinPasswordLength          = 6
	MaxPasswordLength          = 128
	MaxPasswordAgeDays         = 1095
	MaxPasswordReusePrevention = 24
)

// PasswordPolicyKey is the key of the one password policy a project
// stores.
const PasswordPolicyKey = "account"

// PasswordPolicy is the custom password policy of an account (a VWS
// project), stored once per project under PasswordPolicyKey. No stored
// policy means the account has none, as in AWS. UpdateAccountPasswordPolicy
// (#83) writes it, GetAccountPasswordPolicy (#82) reads it and
// DeleteAccountPasswordPolicy (#84) deletes it. It holds no secret.
type PasswordPolicy struct {
	Meta
	MinimumPasswordLength      int  `json:"minimumPasswordLength"`
	RequireSymbols             bool `json:"requireSymbols,omitempty"`
	RequireNumbers             bool `json:"requireNumbers,omitempty"`
	RequireUppercaseCharacters bool `json:"requireUppercaseCharacters,omitempty"`
	RequireLowercaseCharacters bool `json:"requireLowercaseCharacters,omitempty"`
	AllowUsersToChangePassword bool `json:"allowUsersToChangePassword,omitempty"`
	// MaxPasswordAge is in days; 0 means passwords never expire.
	MaxPasswordAge int `json:"maxPasswordAge,omitempty"`
	// PasswordReusePrevention is how many previous passwords cannot be
	// reused; 0 means no check.
	PasswordReusePrevention int  `json:"passwordReusePrevention,omitempty"`
	HardExpiry              bool `json:"hardExpiry,omitempty"`
}

func (PasswordPolicy) Kind() Kind  { return KindPasswordPolicy }
func (PasswordPolicy) Key() string { return PasswordPolicyKey }

// Validate checks the AWS bounds: a minimum length of 6 to 128, a
// maximum age of 0 (none) to 1095 days and a reuse prevention of 0
// (none) to 24.
func (p PasswordPolicy) Validate() error {
	switch {
	case p.MinimumPasswordLength < MinPasswordLength || p.MinimumPasswordLength > MaxPasswordLength:
		return invalid("password policy minimum length %d", p.MinimumPasswordLength)
	case p.MaxPasswordAge < 0 || p.MaxPasswordAge > MaxPasswordAgeDays:
		return invalid("password policy max age %d", p.MaxPasswordAge)
	case p.PasswordReusePrevention < 0 || p.PasswordReusePrevention > MaxPasswordReusePrevention:
		return invalid("password policy reuse prevention %d", p.PasswordReusePrevention)
	}
	return nil
}
