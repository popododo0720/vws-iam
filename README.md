# vws-iam

Identity and access management for VWS: users, groups, roles, JSON policy
evaluation, access keys, STS AssumeRole and MFA (TOTP). console-api calls this
service over gRPC (API in vws-proto) to verify SigV4 requests and authorize
every EC2/S3/IAM call.

Status: Phase 1 design, see the "IAM Phase 1 design" issue.

License: Apache-2.0

## MFA lockout status

GetMfaDevice and ListMfaDevices report `status.failed_attempts` and
`status.locked_until`. These are admin fields: like every MfaDevice call
they are only reached through console-api, which authorizes the caller
with `Authorize(iam:GetMfaDevice | iam:ListMfaDevices, ...)` first, so
only an IAM administrator sees them. The counter resets when the device
locks: the 5th wrong code in a row sets `locked_until` to now+15m and
`failed_attempts` back to 0. `locked_until` is set only while the lockout
runs. Neither field carries the seed or a code.

## Development

```
go test -race ./...
KUBEBUILDER_ASSETS=<dir with kube-apiserver and etcd> go test ./internal/store/kubestore
golangci-lint run
```

See AGENTS.md for the layout and rules, and #1 for the design.
