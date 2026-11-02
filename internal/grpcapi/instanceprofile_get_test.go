package grpcapi_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestGetInstanceProfile: the profile is returned as stored, under its
// stored name for any case of the requested name, with its ARN and the
// stored role it names; another replica sees the same, and the read
// writes nothing. On both store backends.
func TestGetInstanceProfile(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			before := seedInstanceProfile(t, b, "Webserver", "s3access")
			stored := storedProfile(t, b, "Webserver")

			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				for _, name := range []string{"Webserver", "webserver", "WEBSERVER"} {
					got, err := replica.api.GetInstanceProfile(t.Context(), proj, name)
					if err != nil {
						t.Fatalf("GetInstanceProfile(%q): %v", name, err)
					}
					p := got.Profile
					if p.Name != "Webserver" || p.Path != "/app/" || p.ID != before.ID || p.UID != before.UID ||
						!p.Created.Equal(before.Created) || len(p.Roles) != 1 || p.Roles[0] != "s3access" {
						t.Fatalf("GetInstanceProfile(%q) profile = %+v, want it as stored %+v", name, p, before)
					}
					if !strings.HasPrefix(p.ID, "AIPA") {
						t.Fatalf("InstanceProfileId = %q, want an AIPA id", p.ID)
					}
					if want := "arn:vws:iam::" + proj + ":instance-profile/app/Webserver"; got.ARN != want {
						t.Fatalf("Arn = %q, want %q", got.ARN, want)
					}
					if len(got.Roles) != 1 || got.Roles[0].Name != "S3Access" || got.Roles[0].UID == "" ||
						got.Roles[0].AssumeRolePolicy == "" {
						t.Fatalf("Roles = %+v, want the stored S3Access role", got.Roles)
					}
				}
			}
			if again := storedProfile(t, b, "Webserver"); again.Version != stored.Version {
				t.Fatalf("reading wrote the profile: version %q, want %q", again.Version, stored.Version)
			}
		})
	}
}

// TestGetInstanceProfileWithoutRole: a profile that holds no role has no
// roles and no role read; one stored without a path has the root ARN.
func TestGetInstanceProfileWithoutRole(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedProfileAt(t, b, "empty", "")
	got, err := e.api.GetInstanceProfile(t.Context(), proj, "empty")
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile.Name != "empty" || len(got.Profile.Roles) != 0 || len(got.Roles) != 0 {
		t.Fatalf("got %+v, want profile empty without roles", got)
	}
	if want := "arn:vws:iam::" + proj + ":instance-profile/empty"; got.ARN != want {
		t.Fatalf("Arn = %q, want %q", got.ARN, want)
	}
}

// TestGetInstanceProfileDeletedRole: the stale name of a role deleted
// while in the profile (#234) is left out of Roles, not an error.
func TestGetInstanceProfileDeletedRole(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedInstanceProfile(t, b, "web", "Gone")
	got, err := e.api.GetInstanceProfile(t.Context(), proj, "web")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Roles) != 0 || len(got.Profile.Roles) != 1 {
		t.Fatalf("got %+v, want the stored name kept and no role", got)
	}
}

// failingGet fails every Get of kind k with err.
type failingGet struct {
	store.Backend
	k   iam.Kind
	err error
}

func (f failingGet) Get(ctx context.Context, k iam.Kind, key string) (store.Entry, error) {
	if k == f.k {
		return store.Entry{}, f.err
	}
	return f.Backend.Get(ctx, k, key)
}

// TestGetInstanceProfileErrors: a bad project or InstanceProfileName is
// ValidationError before any store access, the AWS name bounds are
// accepted, an unknown profile is NoSuchEntity, and a store failure on
// the profile or a role is InternalFailure, never success.
func TestGetInstanceProfileErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seedProfileAt(t, b, strings.Repeat("p", iam.MaxInstanceProfileNameLen), "/")
	seedProfileAt(t, b, "A+=,.@_-z9", "/")

	get := func(pid, name string) error {
		_, err := e.api.GetInstanceProfile(ctx, pid, name)
		return err
	}
	for _, n := range []string{"", "a b", "a/b", "é", strings.Repeat("p", iam.MaxInstanceProfileNameLen+1)} {
		wantAWS(t, get(proj, n), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, get("Bad_Project", "web"), codes.InvalidArgument, "ValidationError")
	for _, n := range []string{strings.Repeat("p", iam.MaxInstanceProfileNameLen), "A+=,.@_-z9"} {
		if err := get(proj, n); err != nil {
			t.Fatalf("GetInstanceProfile(%q): %v, want found", n, err)
		}
	}
	wantAWS(t, get(proj, "missing"), codes.NotFound, "NoSuchEntity")

	boom := errors.New("backend down")
	for _, k := range []iam.Kind{iam.KindInstanceProfile, iam.KindRole} {
		fb := failingGet{memstore.New(), k, boom}
		fe := newEnvOn(t, fb, &now)
		seedInstanceProfile(t, fb, "web", "r")
		_, err := fe.api.GetInstanceProfile(ctx, proj, "web")
		wantAWS(t, err, codes.Internal, "InternalFailure")
	}
}
