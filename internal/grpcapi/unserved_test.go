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

// TestUnservedRPCsAreUnimplemented: the RPCs vws-proto v0.9.0 added that
// this server does not serve yet answer UNIMPLEMENTED (#100, #102).
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
