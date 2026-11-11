package grpcapi_test

import (
	"context"
	"errors"
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func TestDeletePolicyRefusesPermissionsBoundary(t *testing.T) {
	for _, bk := range renameBackends {
		for _, kind := range []string{"user", "role"} {
			t.Run(bk.name+"/"+kind, func(t *testing.T) {
				b := bk.open()
				now := time.Now().UTC()
				e := newEnvOn(t, b, &now)
				sb := store.Scoped(b, proj)
				arn := seedBoundaryPolicy(t, e, "Boundary", "")
				seedSim(t, b, nil)
				var err error
				if kind == "user" {
					_, err = store.Mutate(t.Context(), sb, "alice", func(u *iam.User) error {
						u.PermissionsBoundary = arn
						return nil
					})
				} else {
					_, err = store.Mutate(t.Context(), sb, "app", func(r *iam.Role) error { r.PermissionsBoundary = arn; return nil })
				}
				if err != nil {
					t.Fatal(err)
				}
				req := &iamv1.DeletePolicyRequest{Name: "projects/" + proj + "/policies/Boundary"}
				for range 2 {
					replica := newEnvOn(t, b, &now)
					_, err := replica.api.DeletePolicy(t.Context(), req)
					wantAWS(t, err, codes.FailedPrecondition, "DeleteConflict")
					if _, err := store.Get[iam.Policy](t.Context(), sb, "Boundary"); err != nil {
						t.Fatalf("refused deletion changed policy: %v", err)
					}
				}
				if kind == "user" {
					err = e.api.DeleteUserBoundary(t.Context(), proj, "alice")
				} else {
					err = e.api.DeleteRoleBoundary(t.Context(), proj, "app")
				}
				if err != nil {
					t.Fatal(err)
				}
				if _, err := e.api.DeletePolicy(t.Context(), req); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// boundaryDeleteOrder injects the other replica immediately before a commit,
// after all reads/checks. No sleeps or scheduler timing determine the order.
type boundaryDeleteOrder struct {
	store.Backend
	beforeDelete   func()
	beforeBoundary func()
}

func (b *boundaryDeleteOrder) Delete(ctx context.Context, kind iam.Kind, key, version string) error {
	if kind == iam.KindPolicy && b.beforeDelete != nil {
		fn := b.beforeDelete
		b.beforeDelete = nil
		fn()
	}
	return b.Backend.Delete(ctx, kind, key, version)
}

func (b *boundaryDeleteOrder) beforeWrite(kind iam.Kind) {
	if (kind == iam.KindUser || kind == iam.KindRole) && b.beforeBoundary != nil {
		fn := b.beforeBoundary
		b.beforeBoundary = nil
		fn()
	}
}

func (b *boundaryDeleteOrder) Update(
	ctx context.Context,
	kind iam.Kind,
	key string,
	spec []byte,
	version string,
) (string, error) {
	b.beforeWrite(kind)
	return b.Backend.Update(ctx, kind, key, spec, version)
}

func (b *boundaryDeleteOrder) UpdateIf(
	ctx context.Context,
	kind iam.Kind,
	key string,
	spec []byte,
	version string,
	pre store.Pre,
) (string, error) {
	b.beforeWrite(kind)
	return b.Backend.UpdateIf(ctx, kind, key, spec, version, pre)
}

func TestBoundaryPolicyDeleteCommitOrders(t *testing.T) {
	for _, bk := range renameBackends {
		for _, kind := range []string{"user", "role"} {
			for _, order := range []string{"boundary-first", "delete-first"} {
				t.Run(bk.name+"/"+kind+"/"+order, func(t *testing.T) {
					b := bk.open()
					now := time.Now().UTC()
					e := newEnvOn(t, b, &now)
					arn := seedBoundaryPolicy(t, e, "Boundary", "")
					seedSim(t, b, nil)
					hook := &boundaryDeleteOrder{Backend: b}
					replica := newEnvOn(t, hook, &now)
					put := func() error {
						if kind == "user" {
							return replica.api.PutUserBoundary(t.Context(), proj, "alice", arn)
						}
						return replica.api.PutRoleBoundary(t.Context(), proj, "app", arn)
					}
					del := func() error {
						_, err := replica.api.DeletePolicy(t.Context(), &iamv1.DeletePolicyRequest{
							Name: "projects/" + proj + "/policies/Boundary",
						})
						return err
					}
					if order == "boundary-first" {
						hook.beforeDelete = func() {
							if err := put(); err != nil {
								t.Fatal(err)
							}
						}
						wantAWS(t, del(), codes.Aborted, "ConcurrentModification")
						wantAWS(t, del(), codes.FailedPrecondition, "DeleteConflict")
					} else {
						hook.beforeBoundary = func() {
							if err := del(); err != nil {
								t.Fatal(err)
							}
						}
						wantAWS(t, put(), codes.NotFound, "NoSuchEntity")
					}
					sb := store.Scoped(b, proj)
					var boundary string
					if kind == "user" {
						v, err := store.Get[iam.User](t.Context(), sb, "alice")
						if err != nil {
							t.Fatal(err)
						}
						boundary = v.Object.PermissionsBoundary
					} else {
						v, err := store.Get[iam.Role](t.Context(), sb, "app")
						if err != nil {
							t.Fatal(err)
						}
						boundary = v.Object.PermissionsBoundary
					}
					_, err := store.Get[iam.Policy](t.Context(), sb, "Boundary")
					if order == "boundary-first" {
						if err != nil || boundary != arn {
							t.Fatalf("boundary winner lost: boundary=%q policy=%v", boundary, err)
						}
					} else if !errors.Is(err, store.ErrNotFound) || boundary != "" {
						t.Fatalf("delete winner left a boundary: boundary=%q policy=%v", boundary, err)
					}
				})
			}
		}
	}
}

// A lost process after reservation leaves no lock or pending state to recover.
// A lost response after publication must replay without another policy write.
type interruptedBoundaryWrite struct {
	store.Backend
	lostReply bool
}

func (b interruptedBoundaryWrite) UpdateIf(
	ctx context.Context,
	kind iam.Kind,
	key string,
	spec []byte,
	version string,
	pre store.Pre,
) (string, error) {
	if kind != iam.KindUser && kind != iam.KindRole {
		return b.Backend.UpdateIf(ctx, kind, key, spec, version, pre)
	}
	if b.lostReply {
		if _, err := b.Backend.UpdateIf(ctx, kind, key, spec, version, pre); err != nil {
			return "", err
		}
	}
	return "", store.ErrUnavailable
}

func TestBoundaryReservationRestart(t *testing.T) {
	for _, bk := range renameBackends {
		for _, kind := range []string{"user", "role"} {
			for _, lostReply := range []bool{false, true} {
				name := "before-commit"
				if lostReply {
					name = "lost-reply"
				}
				t.Run(bk.name+"/"+kind+"/"+name, func(t *testing.T) {
					b := bk.open()
					now := time.Now().UTC()
					e := newEnvOn(t, b, &now)
					arn := seedBoundaryPolicy(t, e, "Boundary", "")
					seedSim(t, b, nil)
					interrupted := newEnvOn(t, interruptedBoundaryWrite{Backend: b, lostReply: lostReply}, &now)
					put := func(e *env) error {
						if kind == "user" {
							return e.api.PutUserBoundary(t.Context(), proj, "alice", arn)
						}
						return e.api.PutRoleBoundary(t.Context(), proj, "app", arn)
					}
					wantAWS(t, put(interrupted), codes.Unavailable, "ServiceUnavailable")
					restarted := newEnvOn(t, b, &now)
					req := &iamv1.DeletePolicyRequest{Name: "projects/" + proj + "/policies/Boundary"}
					if lostReply {
						before, err := store.Get[iam.Policy](t.Context(), store.Scoped(b, proj), "Boundary")
						if err != nil {
							t.Fatal(err)
						}
						if err := put(restarted); err != nil {
							t.Fatal(err)
						}
						after, err := store.Get[iam.Policy](t.Context(), store.Scoped(b, proj), "Boundary")
						if err != nil {
							t.Fatal(err)
						}
						if before.Version != after.Version {
							t.Fatal("replay changed the policy generation")
						}
						_, err = restarted.api.DeletePolicy(t.Context(), req)
						wantAWS(t, err, codes.FailedPrecondition, "DeleteConflict")
					} else {
						if _, err := restarted.api.DeletePolicy(t.Context(), req); err != nil {
							t.Fatal(err)
						}
						wantAWS(t, put(restarted), codes.NotFound, "NoSuchEntity")
					}
				})
			}
		}
	}
}

// publishingDuringScan attempts publication after DeletePolicy scanned, using
// the policy version reserved before DeletePolicy started.
type publishingDuringScan struct {
	store.Backend
	during func(publish func() error)
}

func (b publishingDuringScan) UpdateIf(
	ctx context.Context,
	kind iam.Kind,
	key string,
	spec []byte,
	version string,
	pre store.Pre,
) (string, error) {
	if kind == iam.KindUser || kind == iam.KindRole {
		b.during(func() error {
			_, err := b.Backend.UpdateIf(ctx, kind, key, spec, version, pre)
			return err
		})
	}
	return b.Backend.UpdateIf(ctx, kind, key, spec, version, pre)
}

func TestBoundaryReservationBeforeDeleteScan(t *testing.T) {
	for _, bk := range renameBackends {
		for _, kind := range []string{"user", "role"} {
			t.Run(bk.name+"/"+kind, func(t *testing.T) {
				b := bk.open()
				now := time.Now().UTC()
				e := newEnvOn(t, b, &now)
				arn := seedBoundaryPolicy(t, e, "Boundary", "")
				seedSim(t, b, nil)
				called := false
				writer := publishingDuringScan{Backend: b, during: func(publish func() error) {
					called = true
					deleter := &boundaryDeleteOrder{Backend: b, beforeDelete: func() {
						if err := publish(); !errors.Is(err, store.ErrConflict) {
							t.Fatalf("publication after deletion scan = %v, want conflict", err)
						}
					}}
					replica := newEnvOn(t, deleter, &now)
					_, err := replica.api.DeletePolicy(t.Context(), &iamv1.DeletePolicyRequest{
						Name: "projects/" + proj + "/policies/Boundary",
					})
					if err != nil {
						t.Fatal(err)
					}
				}}
				replica := newEnvOn(t, writer, &now)
				var err error
				if kind == "user" {
					err = replica.api.PutUserBoundary(t.Context(), proj, "alice", arn)
				} else {
					err = replica.api.PutRoleBoundary(t.Context(), proj, "app", arn)
				}
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
				if !called {
					t.Fatal("publication was not attempted during the delete scan")
				}
			})
		}
	}
}
