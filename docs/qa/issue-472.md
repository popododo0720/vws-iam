# Issue 472 protocol prerequisite QA

This PR covers acceptance criterion 1 only. The v0.24.0 protocol interface
requires four test service adapters to be renamed before the MFA work can
land. The added RPCs retain UNIMPLEMENTED behavior. EnableMfaDevice refuses
its newly recognized user preconditions until their atomic implementation
lands, rather than silently dropping them.

## Surface evidence

`internal/grpcapi/unserved_test.go` exercises the gRPC clients and servers
on memstore and a faithfully faked Kubernetes boundary.

`TestEnableMFAPreconditionsUnserved` probes each precondition separately,
malformed input, two deliveries across newly created servers, and exact
stored-device equality after every refused request. The test checks both
the error and a nil response to avoid misleading success output.

Failing-before proof used `git stash push -m issue-472-precondition-proof --
internal/grpcapi/mfa.go`, followed by:

```sh
go test ./internal/grpcapi -run '^TestEnableMFAPreconditionsUnserved$' -count=1 -v
```

Exit 1 on both backends: the call reached TOTP validation and answered
Unauthenticated / InvalidAuthenticationCode instead of Unimplemented.
`git stash pop` restored the refusal; the identical command then exited 0,
with both backend subtests passing. The stash was removed by the pop.

The existing `TestUnservedRPCsAreUnimplemented` additionally checks all six
newly required RPC methods. Existing service tests keep their assertions;
only the four colliding adapter names and their callers changed.

## Checks

Tool versions: Go 1.26.10; golangci-lint 2.14.0.

- `go list -m -versions github.com/popododo0720/vws-proto`: latest tag v0.24.0.
- `go get github.com/popododo0720/vws-proto@v0.24.0 && go mod tidy`: exit 0.
- Unchanged baseline `go test ./... -count=1`: exit 0.
- `go build ./...`: exit 0.
- `go test ./... -count=1`: exit 0.
- `go test -race ./...`: exit 0; gRPC package completed in 130.233 seconds.
- `golangci-lint run --timeout=5m ./...`: exit 0, 0 issues.
- `golangci-lint fmt --diff`: exit 0, no diff.
- `test -z "$(gofmt -l cmd internal)"`: exit 0.
- `VWS_LIB_OFFLINE=1 scripts/vendor-lib.sh check`: exit 0, vendored bytes match;
  offline mode does not confirm the upstream v0.1.1 tag.
- `scripts/guard-agents.sh selftest`: exit 0.
- `scripts/guard.sh correct`: exit 0.
- `scripts/guard_test.sh`: exit 0.
- `scripts/guard-agents.sh archtest`: exit 0; all architecture checks passed.
- `scripts/guard-agents.sh pr-body .issue-472-tmp/pr-body.md`: exit 0.
- `scripts/guard-agents.sh pr-checklist .issue-472-tmp/pr-body.md`: exit 0.
- `scripts/check-english.sh files`: exit 0.
- `git diff --check`: exit 0.
- `go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...`: exit 1;
  existing Go 1.26.10 standard-library finding GO-2026-6859, fixed in Go
  1.26.11. The protocol upgrade changes no Go version or HTTP code.

## Remaining work and limits

Acceptance criteria 2 and 3 remain: implement the atomic user_etag and
expected_user_arn checks and add moved-user, replaced-user, interrupted
enrollment and replay tests for that implementation. This prerequisite
does not claim those criteria. Nonempty MFA preconditions deliberately
answer UNIMPLEMENTED meanwhile. Unconditional enrollment is unchanged.

KUBEBUILDER_ASSETS is unset, so envtest tests retain their normal skip.
Embedded-etcd and fake-Kubernetes tests run in the full suite.

N/A: live check deferred until after phase 1 (owner decision).
Independent verification belongs to the needs-verify reviewer; these are
the author's local checks. No merge or production action was performed.
