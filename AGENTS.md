# AGENTS.md

Rules for anyone changing this repository, human or agent. A rule with an enforcer fails a check when it is broken. A rule marked judgment has no check, so the author and the reviewer carry it. Design: #1.

## Layout

| Package | Owns |
| --- | --- |
| `internal/iam` | Domain types (users, groups, roles, managed policies, access keys, MFA devices), validation, and ARNs. Pure. |
| `internal/store` | The `Backend` interface, typed helpers, and `Mutate` (read, apply, compare-and-swap, retry). `storetest` is the suite every backend passes. |
| `internal/store/memstore`, `internal/store/kubestore` | The two backends. `kubestore` keeps each object in one `iam.vws.popododo0720.io/v1alpha1` custom resource in the service namespace. |
| `internal/secret` | AES-256-GCM sealing under a KEK keyring loaded from the `vws-iam-kek` Secret. The KEK id is stored with each value; associated data binds a value to its owner. |
| `internal/password` | argon2id PHC hashes. |
| `internal/accesskey` | Access keys: create (secret returned once), list, status, delete, at most 2 per user, `GetSigningCredential`. |
| `internal/policy` | Policy parse/validate (`MalformedPolicyDocument`) and evaluation: explicit Deny > Allow > implicit deny, session policies narrow. Pure. |
| `internal/authz` | `Authorize`: gathers user, group, and role policies from the store and evaluates them. |
| `internal/sts` | `AssumeRole` and `GetSessionToken`. The session token is the sealed session (KEK, AES-256-GCM), bound to its `ASIA` key id and its principal's unique id; `Validate` rejects tampered, mismatched, expired, and revoked tokens. `Resolve` derives the `Caller` (MFA, temporary) server-side; `RevokeSessions` stores a cut-off on the user or role. |
| `internal/totp` | RFC 6238 TOTP (SHA-1, 6 digits, 30 s). Pure. |
| `internal/mfa` | Virtual MFA devices: create (seed shown once, stored sealed), enable with two consecutive codes within ±1 step, deactivate, delete, list, `Verify` with ±1 step and a replay guard; 5 wrong codes in a row lock the device for 15 minutes (stored, survives restart). |
| `cmd/vws-iam` | Wiring and flags (`-listen`, `-namespace`, `-kubeconfig`). |
| `deploy/crds`, `deploy/rbac` | The CRDs and the namespaced store `Role`. vws-iam owns the IAM CRD schemas; vws-deploy only syncs them into its chart. |
| `internal/grpcapi` | vws.iam.v1 gRPC server: done-LRO mutations with request_id replay, AWS error codes in ErrorInfo `aws_code`, Authenticate (SigV4 canonical request, secret stays here), Authorize recheck; AssumeRole/GetSessionToken take the caller only from the request's `authentication` oneof (vws-proto v0.3.0): a SigV4 request re-verified here and resolved by `sts.Resolve`, or a console session token (`console_session_token` is root-only for GetSessionToken). Missing is UNAUTHENTICATED. |
| `internal/sigv4` | Pure SigV4 verification. |
| `third_party/vws-proto` | Vendored vws-proto v0.3.0 (9b7e184, see `VENDOR`). |
| `cmd/vws-iam` | `vws-iam` serves; `vws-iam bootstrap` is the idempotent post-helm Job importing the root key. KEK from `VWS_IAM_KEK`/`VWS_IAM_KEK_ID` (or `-kek-dir`). |

## Rules

Every row names its enforcer. `TestAgentsRulesNameAnEnforcer` (internal/archtest) fails on an empty Enforcer cell and logs the Judgment count. Layer rules live in `internal/archtest` (modeled on vws-compute); each rule there must catch a deliberate violation in a probe tree.

| Rule | Enforcer |
| --- | --- |
| `internal/iam`, `internal/policy`, `internal/totp`, and `internal/sigv4` are pure: nothing from this module, Kubernetes, gRPC, or protobuf. | `TestArchitectureRules` |
| `internal/password` imports nothing from this module; `internal/secret` and `internal/store` see only `internal/iam`. | `TestArchitectureRules` |
| Domain services (`internal/accesskey`, `internal/authz`, `internal/sts`, `internal/mfa`) import no transport. | `TestArchitectureRules` |
| Kubernetes client packages stay in `internal/store/kubestore`. | `TestArchitectureRules` |
| gRPC stays in `internal/grpcapi` and `cmd/vws-iam`; protobuf, genproto, vws-proto, and longrunning types stay in `internal/grpcapi`. | `TestArchitectureRules` |
| `internal/grpcapi` uses the `store.Backend` contract, never `kubestore` or `memstore` internals. | `TestArchitectureRules` |
| `GetSigningCredential` (plaintext secret) is referenced only from `internal/accesskey` and `internal/grpcapi`. | `TestArchitectureRules` |
| Production packages do not import `testing`. `storetest` is the one exception. | `TestArchitectureRules` |
| Logs are slog through vws-lib `obs`, wired at the edge; no `log`, no direct sentry-go. No SQL. | `TestArchitectureRules`, `.golangci.yml` depguard |
| vws-lib is the vendored copy in `third_party/vws-lib`. | `TestVendoredLib`, `scripts/vendor-lib.sh check` |
| No trademark or rights notices outside `LICENSE`. | `TestNoTrademarkNotices` |
| Every backend behaves the same: round trip per kind, case-insensitive names, stale writes conflict, invalid objects are never stored, concurrent `Mutate` loses no write. | `storetest.Run` from memstore, kubestore (fake client), and kubestore on envtest with `deploy/crds` |
| No plaintext secret material is stored: access-key secrets and TOTP seeds are `iam.Sealed` ciphertext, passwords are argon2id hashes. | `Validate`, `TestValidateRejectsHostileInput`, `TestSecretIsNeverStoredInPlaintext` |
| Secrets are never logged. | Judgment |
| An access key's secret is stored only sealed; listing never returns it; an inactive key gets no signing credential; a KEK rotation still opens old values and rewraps them. | `TestSecretIsNeverStoredInPlaintext`, `TestInactiveKeyIsRejected`, `TestKEKRotationReadsOldKeyIDAndRewraps` |
| Explicit deny beats allow, nothing is allowed by default, a session policy only narrows, and an unknown principal, unknown policy, or malformed stored policy is an error, never an allow. Wildcard matching is linear. | `TestEvaluateAWSExamples`, `TestSessionPolicyOnlyNarrows`, `TestAuthorizeFailsClosed`, `TestMatchIsLinear`, `FuzzParse` |
| AssumeRole needs both the caller's `sts:AssumeRole` permission and the role's trust; MFA is carried into the session; a session policy narrows; chained sessions last at most 1 h; tokens expire and are tamper-evident. | `TestUntrustedPrincipalIsDenied`, `TestMFAConditionAndPropagation`, `TestSessionPolicyNarrows`, `TestDurationAndNameBounds`, `TestAssumeRoleCredentialsWorkThenExpire`, `TestTokenIsBoundTamperEvidentAndSurvivesRestart` |
| A `Caller` is built only by `Resolve` or a validated session, never from client fields; client-set `aws:MultiFactorAuthPresent` is dropped; `GetSessionToken`/`AssumeRole` verify SerialNumber + TokenCode before granting MFA; `RevokeSessions` invalidates earlier sessions across restarts. | `TestCallerIsDerivedServerSide`, `TestGetSessionTokenVerifiesMFA`, `TestRevokeSessions` |
| STS over gRPC: no `authentication` is UNAUTHENTICATED; the deprecated `caller` field is ignored; a forwarded SigV4 request must be signed for `sts` and this action, inside the X-Amz-Date window, and is accepted once; MFA codes go through `internal/mfa` (replay guard, lockout). | `TestSTSAuthenticationOneof`, `TestSTSMFAIsVerifiedAndLocksOut`, `TestConsoleSessionAuthentication`, `TestAssumeRole`, `TestLoginMFAAndSessions` |
| Wrong codes (Verify and Enable) count toward a stored lockout; a locked device refuses even a correct code until it expires; a success resets the counter. Enable accepts only codes within ±1 step. | `TestFailedAttemptsLockTheDevice`, `TestEnableFailuresCountTowardLockout`, `TestEnableNeedsTwoConsecutiveCodes` |
| TOTP matches the RFC vectors; a code is accepted at most once per device, even under concurrent use; a device belongs to one user; the seed is never stored or listed in plaintext. | `TestRFC6238Vectors`, `TestReusedCodeIsRejected`, `TestConcurrentReplayWinsOnce`, `TestEnableNeedsTwoConsecutiveCodes`, `TestEnrollmentSeedIsSealedAndShownOnce`, `TestMFARequiredPolicyDeniesWithoutMFA` |
| Only `deploy/crds` and `deploy/rbac` manifests; RBAC is a namespaced `Role` without wildcards. vws-iam owns the IAM CRD schemas; vws-deploy only syncs them. | `TestOnlyRBACAndCRDManifests` |
| Code is gofmt and goimports clean and passes the `.golangci.yml` linters. `third_party` is excluded. | `golangci-lint` v2.14.0 in CI, `gofmt -l` step in CI |
| `go test -race ./...` passes. The envtest test skips unless `KUBEBUILDER_ASSETS` is set. | CI `test` job |
| Every rule in this table names an enforcer. | `TestAgentsRulesNameAnEnforcer` |
| A pull request targets `main` and closes an issue. | `scripts/guard-agents.sh pr-base`, `pr-body` (repo-guard) |
| Work on a feature branch. Never commit to `main`. | `direct-push-watch.yml` (after the fact), Judgment before |
| Each commit is one logical change and leaves `go test ./...` passing. | Judgment |

## Insider-risk guardrails

Bots are insider risks too. These rules have no exceptions. Design: `popododo0720/vws-deploy#33`.

1. **Independent verification.** The bot or model that wrote a change does not verify it. Another bot or a person does. This is process, and CI cannot enforce it.
2. **Record.** Every change is an issue, then a PR with `Closes #N`, then commits. The PR body says what changed, how it was verified, and what was not verified. No force-push or history rewrite without the user's approval.
3. **Failing tests.** A new feature is not tested on the happy path alone. It has at least one case each for power loss or restart, idempotent replay, and hostile or boundary input. Otherwise the PR says why one is impossible.
4. **Least privilege.** No push to `main`. Every change is one PR from its own branch off `main`. No stacked PRs and no local merges. Tokens are scoped to this repository. RBAC covers only what the code calls, in a namespaced Role where possible (`vws-deploy` `docs/rbac.md`).
5. **Separate audit.** The author, the verifier, and the merge decision are different. The author never merges its own PR. Merge only when the base is `main` and every check on the head commit is success.
6. **Isolation and stop.** To stop a bot, end its session and revoke its token. Risky work runs only in the box or a throwaway cluster. No access to a production cluster.
7. **Incident disclosure.** A broken rule or an incident is written up in an issue labeled `incident` with cause, impact, fix, and prevention.

Repository items:

- Reboot recovery. All state is in the backend; a restart rereads it (`storetest` `ReopenKeepsState`).
- Idempotent replay. A second create of the same name is `ErrExists`, a stale write is `ErrConflict` (`storetest`).
- Hostile input. Invalid names, paths, unsealed secrets, and non-argon2id hashes are rejected before any write (`TestValidateRejectsHostileInput`, `InvalidObjectIsNotStored`).
- RBAC. `deploy/rbac/role.yaml` lists only the verbs `kubestore` calls.
- No AWS account ID digits anywhere in the repository.
- Checks: `.github/workflows/repo-guard.yml` runs `scripts/guard-agents.sh` on every pull request. `.github/workflows/direct-push-watch.yml` reports a commit that reached `main` without a pull request. Both files are byte-identical across VWS repos; change them only in all repos at once. The Judgment count lives in `TestAgentsRulesNameAnEnforcer`, not in the shared script.
