package grpcapi_test

import (
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
