# vws-iam

Identity and access management for VWS: users, groups, roles, JSON policy
evaluation, access keys, STS AssumeRole and MFA (TOTP). console-api calls this
service over gRPC (API in vws-proto) to verify SigV4 requests and authorize
every EC2/S3/IAM call.

Status: Phase 1 design, see the "IAM Phase 1 design" issue.

License: Apache-2.0

## Session revocation and clocks

RevokeUserSessions and RevokeRoleSessions do not compare replica clocks.
Each revocation bumps a counter on the user or role inside the store's
compare-and-swap, and every STS session token records the counter it read
when it was issued. A session is refused once the stored counter is
higher, so "issued before the revoke" means "read the counter before the
revoke committed", whatever each replica's clock says. A session issued
after the revoke is valid at once, with no grace period.
`sessions_revoke_time` is still reported: it is the revoking replica's
clock, never moves backwards, and is informational only. Tokens issued
before this change carry no counter; for them the old time comparison is
widened by `sigv4.MaxSkew` (15 minutes) until they expire.

## MFA lock renewal

A device lock starts only from wrong codes: the 5th wrong code in a row
(Verify, Enable, console Login or STS with a valid credential) locks the
device for 15 minutes from that failure. Lockouts back off: until a code
is accepted, the next lockout lasts 30 minutes and every one after it 1
hour (`mfa.MaxLockout`), so waiting out each lock leaves 5 guesses per
hour; the lockout count is stored with the device and survives a
restart (#29). An attempt refused with
`Throttling` checks no code, so it never starts a lock. When the user's
own attempt counter is over its limit, a throttled console Login or STS
MFA attempt renews
a lock that is already running to now+15m, but never past 1 hour
(`mfa.MaxLockout`) from the failure that locked it; then the device
unlocks and only 5 new wrong codes lock it again. A throttle by the
source IP alone leaves the lock as it is.

Who can affect a lock: wrong codes need the user's password (console
Login) or one of the user's access keys (STS, which only checks the
caller's own devices). Anyone who knows the user name can trip the
user's attempt limit with wrong passwords and so extend a running lock,
but only up to the 1-hour cap. A holder of a leaked key can still lock
the device again with 5 new wrong codes per lock, as with any lockout;
the fix is to deactivate that key (#48).

## MFA lockout status

GetMfaDevice and ListMfaDevices report `status.failed_attempts` and
`status.locked_until`. These are admin fields: like every MfaDevice call
they are only reached through console-api, which authorizes the caller
with `Authorize(iam:GetMfaDevice | iam:ListMfaDevices, ...)` first, so
only an IAM administrator sees them. The counter resets when the device
locks: the 5th wrong code in a row sets `locked_until` to now+15m (30m,
then 1h, for further lockouts before an accepted code) and
`failed_attempts` back to 0. `locked_until` is set only while the lockout
runs. Neither field carries the seed or a code.

An STS call (AssumeRole, GetSessionToken) with an MFA code whose user,
access key or source IP is over its attempt limit is refused with
`Throttling` (RESOURCE_EXHAUSTED), not AccessDenied. Only when the
user's own counter is over its limit does that throttled attempt renew
a running device lock: `locked_until` becomes now+15m, capped at 1 hour
from the failure that locked it (see "MFA lock renewal"), so the lock
lasts 15 minutes from the last attempt rather than ending with the
attempt-counter window. A throttle never starts a lock. A throttle by the
source IP or access key alone leaves `locked_until` and
`failed_attempts` untouched, so the right code from another IP or key
still works. Console Login renews the same way (#48).

## Development

```
go test -race ./...
golangci-lint run
```

See AGENTS.md for the layout and rules, and #1 for the design.

## Policy simulation compatibility gaps

`SimulateCustomPolicy` currently simulates only the supplied identity policies
and optional permissions boundary. VWS does not model AWS Organizations,
organizational units, service control policies (SCPs), or resource control
policies (RCPs). Consequently, `OrderedOrganizationPolicyInputList` is not
accepted, and results do not claim an `OrganizationsDecisionDetail`. An allow
in this simulator does not establish that an AWS organization would allow the
same request. Do not discard an organization's policy inputs and present the
result as an equivalent evaluation.

The AWS API accepts up to seven ordered SCP levels. Supporting that input in
VWS requires evaluation at each level, explicit-deny precedence, and an allow
at every level, including the resource scoping and conditions of each policy.
That work remains part of #257, alongside resource-policy evaluation,
resource ownership, EC2 scenario validation, and matched resource statements.
The current service layer refuses a supplied `ResourcePolicy` or
`ResourceHandlingOption` with `InvalidInput` rather than ignoring it.

Reference: [AWS SimulateCustomPolicy](https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulateCustomPolicy.html).
