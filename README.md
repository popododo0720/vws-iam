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

## MFA lockout status

GetMfaDevice and ListMfaDevices report `status.failed_attempts` and
`status.locked_until`. These are admin fields: like every MfaDevice call
they are only reached through console-api, which authorizes the caller
with `Authorize(iam:GetMfaDevice | iam:ListMfaDevices, ...)` first, so
only an IAM administrator sees them. The counter resets when the device
locks: the 5th wrong code in a row sets `locked_until` to now+15m and
`failed_attempts` back to 0. `locked_until` is set only while the lockout
runs. Neither field carries the seed or a code.

An STS call (AssumeRole, GetSessionToken) with an MFA code whose user,
access key or source IP is over its attempt limit is refused with
`Throttling` (RESOURCE_EXHAUSTED), not AccessDenied. Only when the
user's own counter is over its limit does that throttled attempt renew
the device lock: `locked_until` becomes now+15m, so the lock lasts 15
minutes from the last attempt rather than ending with the attempt-counter
window. A throttle by the source IP or access key alone leaves
`locked_until` and `failed_attempts` untouched, so the right code from
another IP or key still works. Console Login does not renew the device
lock (#48).

## Development

```
go test -race ./...
KUBEBUILDER_ASSETS=<dir with kube-apiserver and etcd> go test ./internal/store/kubestore
golangci-lint run
```

See AGENTS.md for the layout and rules, and #1 for the design.
