package grpcapi_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func getProfileRPC(t *testing.T, e *env, name string) (*iamv1.InstanceProfile, error) {
	t.Helper()
	return e.profiles.GetInstanceProfile(t.Context(), &iamv1.GetInstanceProfileRequest{Name: name})
}

// TestGetInstanceProfileRPC: InstanceProfileService.GetInstanceProfile
// returns the stored profile under its stored name for any case of the
// requested one, with its envelope, path, ARN, AIPA id and the role it
// holds both as a resource name and as the Role GetRole returns. A second
// server on the same store (another replica, or this one restarted) gives
// the same answer, and the read writes nothing. On both store backends.
func TestGetInstanceProfileRPC(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			role, err := e.roles.GetRole(t.Context(), &iamv1.GetRoleRequest{Name: parentName + "/roles/S3Access"})
			if err != nil {
				t.Fatal(err)
			}
			before := seedInstanceProfile(t, b, "Webserver", "s3access")
			stored := storedProfile(t, b, "Webserver")

			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				for _, n := range []string{"Webserver", "webserver", "WEBSERVER"} {
					got, err := getProfileRPC(t, replica, parentName+"/instanceProfiles/"+n)
					if err != nil {
						t.Fatalf("GetInstanceProfile(%q): %v", n, err)
					}
					if got.GetName() != parentName+"/instanceProfiles/Webserver" || got.GetUid() != before.UID ||
						got.GetGeneration() != 1 || got.GetEtag() != stored.Version ||
						!got.GetCreateTime().AsTime().Equal(before.Created) {
						t.Fatalf("GetInstanceProfile(%q) envelope = %v, want the stored profile at %q", n, got, stored.Version)
					}
					if got.GetSpec().GetPath() != "/app/" ||
						!slices.Equal(got.GetSpec().GetRoles(), []string{parentName + "/roles/S3Access"}) {
						t.Fatalf("spec = %v, want path /app/ and the S3Access role", got.GetSpec())
					}
					st := got.GetStatus()
					if st.GetArn() != "arn:vws:iam::"+proj+":instance-profile/app/Webserver" ||
						st.GetUniqueId() != before.ID || !strings.HasPrefix(st.GetUniqueId(), "AIPA") ||
						st.GetObserved().GetGeneration() != 1 {
						t.Fatalf("status = %v, want ARN, AIPA id %s and observed generation 1", st, before.ID)
					}
					if len(st.GetRoles()) != 1 || !proto.Equal(st.GetRoles()[0], role) {
						t.Fatalf("status.roles = %v, want [%v]", st.GetRoles(), role)
					}
				}
			}
			if again := storedProfile(t, b, "Webserver"); again.Version != stored.Version {
				t.Fatalf("reading wrote the profile: version %q, want %q", again.Version, stored.Version)
			}
		})
	}
}

// TestGetInstanceProfileRPCRoles: a profile without a role, and one that
// still names a deleted role (#234), list no role in spec or status.
func TestGetInstanceProfileRPCRoles(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedInstanceProfile(t, b, "empty")
	seedInstanceProfile(t, b, "stale", "Gone")
	for _, n := range []string{"empty", "stale"} {
		got, err := getProfileRPC(t, e, parentName+"/instanceProfiles/"+n)
		if err != nil {
			t.Fatalf("GetInstanceProfile(%q): %v", n, err)
		}
		if len(got.GetSpec().GetRoles()) != 0 || len(got.GetStatus().GetRoles()) != 0 {
			t.Fatalf("GetInstanceProfile(%q) = %v, want no role", n, got)
		}
	}
}

// TestGetInstanceProfileRPCErrors: a name that is not
// projects/{project}/instanceProfiles/{id}, a bad project and an
// InstanceProfileName outside the AWS rule are INVALID_ARGUMENT
// (ValidationError) and the 128-character bound is accepted; an unknown
// profile is NOT_FOUND (NoSuchEntity), and a store failure on the profile
// or its role is INTERNAL without backend detail, never a profile.
func TestGetInstanceProfileRPCErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	longest := strings.Repeat("p", iam.MaxInstanceProfileNameLen)
	seedProfileAt(t, b, longest, "/")

	for _, n := range []string{
		"", "web", parentName, parentName + "/roles/web", parentName + "/instanceProfiles/",
		parentName + "/instanceProfiles/a/b", "projects/Bad_Project/instanceProfiles/web",
		parentName + "/instanceProfiles/a b", parentName + "/instanceProfiles/é",
		parentName + "/instanceProfiles/" + longest + "p",
	} {
		_, err := getProfileRPC(t, e, n)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	}
	if _, err := getProfileRPC(t, e, parentName+"/instanceProfiles/"+longest); err != nil {
		t.Fatalf("GetInstanceProfile(128 characters): %v, want found", err)
	}
	_, err := getProfileRPC(t, e, parentName+"/instanceProfiles/missing")
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")

	for _, k := range []iam.Kind{iam.KindInstanceProfile, iam.KindRole} {
		fb := failingGet{memstore.New(), k, errors.New("backend down")}
		fe := newEnvOn(t, fb, &now)
		seedInstanceProfile(t, fb, "web", "r")
		got, err := getProfileRPC(t, fe, parentName+"/instanceProfiles/web")
		if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "backend down") || got != nil {
			t.Fatalf("store failure on %s: %v, %v; want a bare INTERNAL and no profile", k, got, err)
		}
	}
}
