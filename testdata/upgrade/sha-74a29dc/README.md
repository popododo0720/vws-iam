# Upgrade fixtures: sha-74a29dc

IAM custom resources written by the vws-iam release pinned as `sha-74a29dc`
in vws-deploy (`charts/vws/values.yaml`). `TestPreviousReleaseRecordsDecode`
loads them into envtest with the current `deploy/crds` and reads every field
through the current decode path.

Tag: sha-74a29dc
Commit: 74a29dc134568142c4c7dbd7ca71739a60057e90
Command: `git archive 74a29dc134568142c4c7dbd7ca71739a60057e90 | tar -x -C /tmp/vws-iam-74a29dc`, then `go run ./cmd/capturefixtures` from that tree against envtest with its `deploy/crds`; the throwaway harness created each record through that commit's `internal/store` and `kubestore`, sealed the fixture secrets with the KEK below, and wrote one JSON CR per object.
KEK id: fixture-kek

The throwaway capture tree is not committed. Its KEK is 32 bytes of `0x42`,
so the sealed values open only with this synthetic key. The records were
written in project `acme`; `IamAccessKeyIndex`, `IamSession`, `IamOperation`,
`IamReplayEntry` and `IamAttemptCounter` are unscoped.

`metadata.name` and the `iam.vws.popododo0720.io/key` annotation are kept.
`metadata.resourceVersion`, `metadata.uid`, `metadata.creationTimestamp` and
`metadata.managedFields` are stripped.

Regenerate only at a release bump, with the new release's tag, commit and KEK
id. Never capture a production credential, password hash, session token or
KEK.
