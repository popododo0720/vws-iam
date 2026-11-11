package grpcapi_test

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestUnservedRPCsAreUnimplemented: the RPCs vws-proto v0.9.0 to v0.24.0
// added that this server does not serve yet answer UNIMPLEMENTED (#94 to
// #108).
func TestUnservedRPCsAreUnimplemented(t *testing.T) {
	e := newEnv(t)
	_, err := e.roles.PutRolePermissionsBoundary(t.Context(), &iamv1.PutRolePermissionsBoundaryRequest{
		Name: parentName + "/roles/r", PermissionsBoundary: "arn:vws:iam::" + proj + ":policy/p",
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("PutRolePermissionsBoundary: %v, want Unimplemented", err)
	}
	_, err = e.mfa.ResyncMfaDevice(t.Context(), &iamv1.ResyncMfaDeviceRequest{
		Parent: parentName, UserName: "u", SerialNumber: "arn:vws:iam::" + proj + ":mfa/u",
		AuthenticationCode_1: "123456", AuthenticationCode_2: "234567",
	})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("ResyncMfaDevice: %v, want Unimplemented", err)
	}
	_, err = e.token.GetAccessKeyInfo(t.Context(), &iamv1.GetAccessKeyInfoRequest{AccessKeyId: "AKIAAAAAAAAAAAAAAAAA"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("GetAccessKeyInfo: %v, want Unimplemented", err)
	}
	ctx := t.Context()
	for name, call := range map[string]func() error{
		"ListEntitiesForPolicy": func() error {
			_, err := e.policies.ListEntitiesForPolicy(ctx, &iamv1.ListEntitiesForPolicyRequest{})
			return err
		},
		"SimulatePrincipalPolicy": func() error {
			_, err := e.policies.SimulatePrincipalPolicy(ctx, &iamv1.SimulatePrincipalPolicyRequest{})
			return err
		},
		"DeleteInstanceProfile": func() error {
			_, err := e.profiles.DeleteInstanceProfile(ctx, &iamv1.DeleteInstanceProfileRequest{})
			return err
		},
		"DeleteUserPermissionsBoundary": func() error {
			_, err := e.users.DeleteUserPermissionsBoundary(ctx, &iamv1.DeleteUserPermissionsBoundaryRequest{})
			return err
		},
		"PutUserPermissionsBoundary": func() error {
			_, err := e.users.PutUserPermissionsBoundary(ctx, &iamv1.PutUserPermissionsBoundaryRequest{})
			return err
		},
		"DeleteRolePermissionsBoundary": func() error {
			_, err := e.roles.DeleteRolePermissionsBoundary(ctx, &iamv1.DeleteRolePermissionsBoundaryRequest{})
			return err
		},
		"CreateServiceLinkedRole": func() error {
			_, err := e.roles.CreateServiceLinkedRole(ctx, &iamv1.CreateServiceLinkedRoleRequest{})
			return err
		},
		"DeleteServiceLinkedRole": func() error {
			_, err := e.roles.DeleteServiceLinkedRole(ctx, &iamv1.DeleteServiceLinkedRoleRequest{})
			return err
		},
		"AssumeRoleWithSAML": func() error {
			_, err := e.token.AssumeRoleWithSAML(ctx, &iamv1.AssumeRoleWithSAMLRequest{})
			return err
		},
		"AssumeRoleWithWebIdentity": func() error {
			_, err := e.token.AssumeRoleWithWebIdentity(ctx, &iamv1.AssumeRoleWithWebIdentityRequest{})
			return err
		},
		"GetFederationToken": func() error {
			_, err := e.token.GetFederationToken(ctx, &iamv1.GetFederationTokenRequest{})
			return err
		},
		"AddRoleToInstanceProfile": func() error {
			_, err := e.profiles.AddRoleToInstanceProfile(ctx, &iamv1.AddRoleToInstanceProfileRequest{})
			return err
		},
	} {
		if err := call(); status.Code(err) != codes.Unimplemented {
			t.Errorf("%s: %v, want Unimplemented", name, err)
		}
	}
}

// TestSetLoginProfileModeFailsClosed: until #326, SetLoginProfile serves
// only the upsert mode. CREATE_ONLY and MUST_EXIST are UNIMPLEMENTED and an
// unknown mode is INVALID_ARGUMENT; neither writes the password.
func TestSetLoginProfileModeFailsClosed(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	u := e.createUser(t, t.Context(), "erin")
	hash := func() string {
		t.Helper()
		got, err := store.Get[iam.User](t.Context(), store.Scoped(b, proj), "erin")
		if err != nil {
			t.Fatal(err)
		}
		return got.Object.PasswordHash
	}
	set := func(mode iamv1.LoginProfileWriteMode) error {
		_, err := e.users.SetLoginProfile(t.Context(), &iamv1.SetLoginProfileRequest{
			Name: u.GetName(), Password: "Correct-Horse-9", Mode: mode,
		})
		return err
	}
	for _, m := range []iamv1.LoginProfileWriteMode{
		iamv1.LoginProfileWriteMode_LOGIN_PROFILE_WRITE_MODE_CREATE_ONLY,
		iamv1.LoginProfileWriteMode_LOGIN_PROFILE_WRITE_MODE_MUST_EXIST,
	} {
		if err := set(m); status.Code(err) != codes.Unimplemented {
			t.Fatalf("mode %v: %v, want Unimplemented", m, err)
		}
	}
	wantErr(t, set(iamv1.LoginProfileWriteMode(99)), codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
	if h := hash(); h != "" {
		t.Fatalf("a refused mode stored a password hash %q", h)
	}
	for _, m := range []iamv1.LoginProfileWriteMode{
		iamv1.LoginProfileWriteMode_LOGIN_PROFILE_WRITE_MODE_UNSPECIFIED,
		iamv1.LoginProfileWriteMode_LOGIN_PROFILE_WRITE_MODE_UPSERT,
	} {
		if err := set(m); err != nil {
			t.Fatalf("mode %v: %v", m, err)
		}
	}
	if hash() == "" {
		t.Fatal("upsert stored no password hash")
	}
}

// TestUnservedFieldsFailClosed: the request fields vws-proto v0.10.0 added
// that this server does not honor yet (the renames of #134, the login
// profile preconditions of #340) answer UNIMPLEMENTED and change nothing,
// so a request is never served as if the field were unset.
func TestUnservedFieldsFailClosed(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	u := e.createUser(t, ctx, "erin")
	e.createGroupWith(t, "ops")
	const pw = "Correct-Horse-9"
	if _, err := e.users.SetLoginProfile(ctx, &iamv1.SetLoginProfileRequest{Name: u.GetName(), Password: pw}); err != nil {
		t.Fatal(err)
	}
	before, err := store.Get[iam.User](ctx, store.Scoped(b, proj), "erin")
	if err != nil {
		t.Fatal(err)
	}
	g, err := store.Get[iam.Group](ctx, store.Scoped(b, proj), "ops")
	if err != nil {
		t.Fatal(err)
	}

	calls := map[string]func() error{
		"UpdateUser new_user_name": func() error {
			_, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
				User: &iamv1.User{Name: u.GetName()}, NewUserName: "frank",
			})
			return err
		},
		"UpdateGroup new_group_name": func() error {
			_, err := e.groups.UpdateGroup(ctx, &iamv1.UpdateGroupRequest{
				Group: &iamv1.Group{Name: groupName("ops")}, NewGroupName: "dev",
			})
			return err
		},
		"SetLoginProfile expected_user_arn": func() error {
			_, err := e.users.SetLoginProfile(ctx, &iamv1.SetLoginProfileRequest{
				Name: u.GetName(), Password: "Other-Horse-10", ExpectedUserArn: u.GetStatus().GetArn(),
			})
			return err
		},
		"SetLoginProfile user_etag": func() error {
			_, err := e.users.SetLoginProfile(ctx, &iamv1.SetLoginProfileRequest{
				Name: u.GetName(), Password: "Other-Horse-10", UserEtag: u.GetEtag(),
			})
			return err
		},
		"DeleteLoginProfile expected_user_arn": func() error {
			_, err := e.users.DeleteLoginProfile(ctx, &iamv1.DeleteLoginProfileRequest{
				Name: u.GetName(), ExpectedUserArn: u.GetStatus().GetArn(),
			})
			return err
		},
		"DeleteLoginProfile user_etag": func() error {
			_, err := e.users.DeleteLoginProfile(ctx, &iamv1.DeleteLoginProfileRequest{
				Name: u.GetName(), UserEtag: u.GetEtag(),
			})
			return err
		},
	}
	for name, call := range calls {
		if err := call(); status.Code(err) != codes.Unimplemented {
			t.Errorf("%s: %v, want Unimplemented", name, err)
		}
	}

	after, err := store.Get[iam.User](ctx, store.Scoped(b, proj), "erin")
	if err != nil {
		t.Fatal(err)
	}
	if after.Version != before.Version || after.Object.PasswordHash != before.Object.PasswordHash {
		t.Fatalf("a refused request changed the user: %+v, was %+v", after, before)
	}
	if _, err := store.Get[iam.User](ctx, store.Scoped(b, proj), "frank"); err == nil {
		t.Fatal("a refused rename created the new user")
	}
	gAfter, err := store.Get[iam.Group](ctx, store.Scoped(b, proj), "ops")
	if err != nil || gAfter.Version != g.Version {
		t.Fatalf("a refused rename changed the group: %+v %v", gAfter, err)
	}
	if _, err := store.Get[iam.Group](ctx, store.Scoped(b, proj), "dev"); err == nil {
		t.Fatal("a refused rename created the new group")
	}
}
