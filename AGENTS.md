# AGENTS.md

Rules for anyone changing this repository, human or agent. A rule with an enforcer fails a check when it is broken. A rule marked judgment has no check, so the author and the reviewer carry it. Design: #1.

## Layout

| Package | Owns |
| --- | --- |
| `internal/iam` | Domain types (users, groups, roles, managed policies, access keys, MFA devices), validation, and ARNs. Pure. |
| `internal/store` | The `Backend` interface, typed helpers, and `Mutate` (read, apply, compare-and-swap, retry). `storetest` is the suite every backend passes. |
| `internal/store/memstore`, `internal/store/kubestore` | The two backends. `kubestore` keeps each object in one `iam.vws.popododo0720.io/v1alpha1` custom resource in the service namespace. |
| `internal/grpcapi` | The gRPC edge. `vws/iam/v1` comes from vws-proto#24; until then only `grpc.health.v1`. |
| `internal/secret` | AES-256-GCM sealing under a KEK keyring loaded from the `vws-iam-kek` Secret. The KEK id is stored with each value; associated data binds a value to its owner. |
| `internal/password` | argon2id PHC hashes. |
| `internal/accesskey` | Access keys: create (secret returned once), list, status, delete, at most 2 per user, `GetSigningCredential`. |
| `internal/policy` | Policy parse/validate (`MalformedPolicyDocument`) and evaluation: explicit Deny > Allow > implicit deny, session policies narrow. Pure. |
| `internal/authz` | `Authorize`: gathers user, group, and role policies from the store and evaluates them. |
| `cmd/vws-iam` | Wiring and flags (`-listen`, `-namespace`, `-kubeconfig`). |
| `deploy/crds`, `deploy/rbac` | The CRDs and the namespaced store `Role`. The chart lives in vws-deploy. |

## Rules

Every row names its enforcer. `scripts/guard-agents.sh judgment` fails on an empty Enforcer cell and prints the Judgment count in CI. Layer rules live in `internal/archtest` (modeled on vws-compute); each rule there must catch a deliberate violation in a probe tree.

| Rule | Enforcer |
| --- | --- |
| `internal/iam` and `internal/policy` are pure: nothing from this module, Kubernetes, gRPC, or protobuf. | `TestArchitectureRules` |
| `internal/password` imports nothing from this module; `internal/secret` and `internal/store` see only `internal/iam`. | `TestArchitectureRules` |
| Domain services (`internal/accesskey`, `internal/authz`) import no transport. | `TestArchitectureRules` |
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
| Only `deploy/crds` and `deploy/rbac` manifests; RBAC is a namespaced `Role` without wildcards. vws-iam owns the IAM CRD schemas; vws-deploy only syncs them. | `TestOnlyRBACAndCRDManifests` |
| Code is gofmt and goimports clean and passes the `.golangci.yml` linters. `third_party` is excluded. | `golangci-lint` v2.14.0 in CI, `gofmt -l` step in CI |
| `go test -race ./...` passes. The envtest test skips unless `KUBEBUILDER_ASSETS` is set. | CI `test` job |
| Every rule in this table names an enforcer. | `scripts/guard-agents.sh judgment` in CI |
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
- Checks: `.github/workflows/repo-guard.yml` runs `scripts/guard-agents.sh` on every pull request. `.github/workflows/direct-push-watch.yml` reports a commit that reached `main` without a pull request. Both files are copied as-is from `vws-compute`; the script adds the `judgment` command (#25), to be upstreamed to vws-compute.
