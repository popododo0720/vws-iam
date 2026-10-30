# Durable shared state for IAM replicas

Part of #110. This note records the storage decision behind the
`-store` flag in `cmd/vws-iam`.

## Problem

vws-iam ran with two replicas while each replica kept state in memory.
A user or access key written on one replica was not visible on the
other, and a pod restart lost all state. AWS IAM is durable and serves
the same data from every endpoint after propagation.

## Options considered

| Option | Shared across replicas | Survives restart | Cost |
| --- | --- | --- | --- |
| In-memory per replica (old behavior) | No | No | None |
| PVC file store, one writer | Only with a single leader | Yes | Leader election, ReadWriteOnce limits scale-out, new backup path |
| Single replica, in memory | Yes (one copy) | No | No HA |
| Kubernetes custom resources (`kubestore`) | Yes | Yes (etcd) | Needs CRDs and a namespaced Role |

## Decision

Use the existing `kubestore` backend whenever vws-iam runs in a pod.
No new backend and no leader are needed:

- Every IAM object, STS revocation, replay entry, attempt counter and
  long-running operation is a custom resource in the
  `iam.vws.popododo0720.io` group (`deploy/crds/iam.yaml`), in one
  namespace.
- Reads go straight to the API server without an informer cache, so a
  write on one replica is visible to the next read on any replica.
- Writes use resourceVersion compare-and-swap
  (`internal/store/kubestore/kubestore.go`), so concurrent replicas
  cannot overwrite each other. Transient API errors are retried with
  bounded backoff (`store.WithRetry`).
- Secret material is encrypted with the KEK keyring before it is
  stored. The kube store refuses to start with an ephemeral KEK, because
  a restart would make stored secrets unreadable.

## Backend selection

`-store` takes `auto` (default), `kube` or `memory`:

- `auto` picks `kube` when `-namespace` is set or the process runs in a
  pod (`KUBERNETES_SERVICE_HOST` is set); otherwise `memory`.
- The namespace comes from `-namespace`, then `POD_NAMESPACE`, then the
  service account namespace file. A pod with no namespace fails startup
  instead of silently falling back to memory.
- `memory` keeps state in one process only and logs a warning. It is for
  local runs and tests, never for replicas.

Before serving, the store is probed with exponential backoff, each try
under its own deadline. A missing CRD or Role stops the rollout, so the
old pods keep serving instead of new pods returning errors. The same
probe backs `/readyz`.

## Restart and upgrade safety

- Objects written by a previous release decode unchanged
  (`TestUpgradeKeepsPersistedState`, `TestPreviousReleaseRecordsDecode`).
- The root-key bootstrap is idempotent: an existing key is kept
  (`store.ErrExists` is not an error).
- Deployments that ran in memory had no persisted state, so there is
  nothing to migrate.

## Deployment requirements

Owned by vws-deploy, listed here so the chart can be checked against it:

1. Install `deploy/crds` and `deploy/rbac` (namespaced Role, only the
   verbs the store calls).
2. Mount the service account token, or set `POD_NAMESPACE` from
   `metadata.namespace`.
3. Provide the KEK through the Secret-backed environment or `-kek-dir`.
4. Raise `replicas` above one only after steps 1 to 3.

## Evidence

- `TestReplicasShareDurableState` (envtest) writes a user on one replica
  and reads it from another. It failed before the change with
  `replica B does not see the user written on A: not found`.
- Live evidence on the vws-test cluster (users and keys survive a pod
  restart and are visible from every replica) is still open. Field
  checks are paused until further notice, so this note does not claim it.
