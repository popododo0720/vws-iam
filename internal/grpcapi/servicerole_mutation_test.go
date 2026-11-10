package grpcapi_test

import (
	"reflect"
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func TestServiceLinkedRoleMutations(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			r := seedLinkedRole(t, b, "AWSServiceRoleForLexBots")
			name := parentName + "/roles/" + r.Name
			sb := store.Scoped(b, proj)
			before, err := store.Get[iam.Role](t.Context(), sb, r.Name)
			if err != nil {
				t.Fatal(err)
			}
			arn := seedBoundaryPolicy(t, newEnvOn(t, b, &now), "Boundary", "")
			for range 2 {
				e := newEnvOn(t, b, &now)
				for _, path := range []string{
					"spec.path",
					"spec.assume_role_policy",
					"spec.max_session_duration_seconds",
					"spec.attached_policies",
					"spec.inline_policies",
					"labels",
				} {
					for _, validate := range []bool{false, true} {
						_, err := e.roles.UpdateRole(t.Context(), &iamv1.UpdateRoleRequest{
							Role: &iamv1.Role{
								Name:   name,
								Labels: map[string]string{"bad": "change"},
								Spec: &iamv1.RoleSpec{
									Path:                      "/new/",
									AssumeRolePolicy:          slrTrust,
									MaxSessionDurationSeconds: 7200,
									InlinePolicies:            map[string]string{"new": slrInline},
								},
							}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{path}}, ValidateOnly: validate,
						})
						wantAWS(t, err, codes.FailedPrecondition, "UnmodifiableEntity")
					}
				}
				_, err := e.roles.UpdateRole(t.Context(), &iamv1.UpdateRoleRequest{
					Role:       &iamv1.Role{Name: name, Spec: &iamv1.RoleSpec{Description: "not atomic"}},
					UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.description", "spec.inline_policies"}},
				})
				wantAWS(t, err, codes.FailedPrecondition, "UnmodifiableEntity")
				_, err = e.roles.UpdateRole(t.Context(), &iamv1.UpdateRoleRequest{
					Role: &iamv1.Role{
						Name:   name,
						Labels: map[string]string{"bad": "change"},
						Spec:   &iamv1.RoleSpec{Description: "not atomic", InlinePolicies: map[string]string{"new": slrInline}},
					},
					UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.description", "spec.inline_policies"}},
				})
				wantAWS(t, err, codes.FailedPrecondition, "UnmodifiableEntity")
				_, err = e.roles.RevokeRoleSessions(t.Context(), &iamv1.RevokeRoleSessionsRequest{Name: name})
				wantAWS(t, err, codes.FailedPrecondition, "UnmodifiableEntity")
				err = e.api.DeleteRoleBoundary(t.Context(), proj, r.Name)
				wantAWS(t, err, codes.FailedPrecondition, "UnmodifiableEntity")
				err = e.api.PutRoleBoundary(t.Context(), proj, r.Name, arn)
				wantAWS(t, err, codes.FailedPrecondition, "UnmodifiableEntity")
			}
			after, err := store.Get[iam.Role](t.Context(), sb, r.Name)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("rejected mutations changed role: %+v %v", after, err)
			}
			e := newEnvOn(t, b, &now)
			_, err = e.roles.UpdateRole(t.Context(), &iamv1.UpdateRoleRequest{
				Role:       &iamv1.Role{Name: name, Spec: &iamv1.RoleSpec{Description: "allowed description"}},
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.description"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			updated, err := store.Get[iam.Role](t.Context(), sb, r.Name)
			if err != nil || updated.Object.Description != "allowed description" ||
				updated.Object.LinkedService != r.LinkedService || updated.Object.AssumeRolePolicy != r.AssumeRolePolicy {
				t.Fatalf("description update: %+v %v", updated, err)
			}
		})
	}
}

func TestCreateRoleReservedServicePath(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			for _, path := range []string{iam.ServiceRolePathPrefix, iam.ServiceRolePath(slrService)} {
				_, err := e.roles.CreateRole(t.Context(), &iamv1.CreateRoleRequest{
					Parent: parentName,
					RoleId: "spoof",
					Role:   &iamv1.Role{Spec: &iamv1.RoleSpec{Path: path, AssumeRolePolicy: slrTrust}},
				})
				wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
				_, err = e.roles.UpdateRole(t.Context(), &iamv1.UpdateRoleRequest{
					Role: &iamv1.Role{
						Name: parentName + "/roles/spoof",
						Spec: &iamv1.RoleSpec{Path: path, AssumeRolePolicy: slrTrust},
					},
					AllowMissing: true,
					UpdateMask:   &fieldmaskpb.FieldMask{Paths: []string{"spec.path", "spec.assume_role_policy"}},
				})
				wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
			}
			all, err := store.List[iam.Role](t.Context(), store.Scoped(b, proj))
			if err != nil || len(all) != 0 {
				t.Fatalf("stored spoofed role: %v %v", all, err)
			}
			_, err = e.roles.UpdateRole(t.Context(), &iamv1.UpdateRoleRequest{
				Role: &iamv1.Role{
					Name: parentName + "/roles/AWSServiceRoleForOrdinary",
					Spec: &iamv1.RoleSpec{Path: "/service-role/", AssumeRolePolicy: slrTrust},
				},
				AllowMissing: true,
				UpdateMask:   &fieldmaskpb.FieldMask{Paths: []string{"spec.path", "spec.assume_role_policy"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			plain, err := store.Get[iam.Role](t.Context(), store.Scoped(b, proj), "AWSServiceRoleForOrdinary")
			if err != nil || plain.Object.ServiceLinked() {
				t.Fatalf("upsert created linked role: %+v %v", plain, err)
			}
		})
	}
}
