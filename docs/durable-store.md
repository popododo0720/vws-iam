# Durable shared state for IAM replicas

Part of #110. Since #450 and #451 the shared store is etcd
(`internal/store/etcdstore`). This note records the storage decision
behind the `-store` flag in `cmd/vws-iam`.

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
| Shared etcd | Yes | Yes | Client mutual TLS and systemd credentials |

## Decision

Use the shared etcd backend for every replica. Each IAM object occupies
one key under the configured prefix. Writes use etcd transactions and
modification revisions for compare-and-swap, including conditional writes
on another object. Secret material is encrypted with the KEK keyring
before it is stored; the TLS client files and KEK come from systemd
credentials so restarts can read existing data.

## Backend selection

`-store` takes `etcd` (default) or `memory`; `kube`, `auto`,
`-namespace` and `-kubeconfig` are refused:

- `etcd` connects to the `-etcd-endpoints` (comma-separated
  `https://host:port`) and keeps every object under `-etcd-prefix`
  (default `/vws/iam`). The client TLS and the KEK come only from
  `$CREDENTIALS_DIRECTORY`, which systemd fills from `LoadCredential=`:
  `etcd-ca.pem`, `etcd-client.pem`, `etcd-client-key.pem`, and the KEK
  directory credential `kek` (`kek_active` holding the active id,
  `kek_<id>` the base64 of 32 bytes for each key). A missing file fails
  startup with an error naming it.
- `memory` keeps state in one process only and logs a warning. It is for
  local runs and tests, never for replicas.

Before serving, the store is probed with exponential backoff, each try
under its own deadline. An unreachable etcd or a refused client
certificate fails startup instead of serving errors. The same probe
backs `/readyz`.

## Restart and upgrade safety

- Objects written by a previous release decode unchanged
  (`TestPreviousReleaseRecordsDecode`).
- The root-key bootstrap is idempotent: an existing key is kept
  (`store.ErrExists` is not an error).
- Deployments that ran in memory had no persisted state, so there is
  nothing to migrate.

## Deployment requirements

Owned by the installer (`vws install`), listed here so the unit can be
checked against it:

1. Run etcd with client mutual TLS and give vws-iam a client
   certificate it accepts.
2. Pass `-store=etcd -etcd-endpoints https://...` and load the
   credentials with `LoadCredential=`: `etcd-ca.pem`, `etcd-client.pem`,
   `etcd-client-key.pem` and the KEK directory as `kek`.
3. Run more than one replica only on the same etcd, prefix and KEK.

## Evidence

- `TestReplicasShareDurableState` (embedded etcd over mutual TLS) writes
  a user on one replica and reads it from another and from a restarted
  one.
- `TestEtcdStoreServes` starts `vws-iam -store etcd` against that etcd
  and gets SERVING; `TestMissingCredentialFailsStartup` removes each
  credential file in turn.
- Live evidence is deferred until after phase 1 (owner decision).
