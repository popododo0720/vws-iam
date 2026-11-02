package grpcapi_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestCreateInstanceProfile: a new profile has the requested name and
// path, an AIPA id, the request time and no role; it is returned with its
// ARN, stored as returned, and every replica reads it back. A name taken
// in any case is EntityAlreadyExists and the stored profile stays. On both
// store backends.
func TestCreateInstanceProfile(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 4, 0, 0, 0, time.UTC)
			e := newEnvOn(t, b, &now)
			got, err := e.api.CreateInstanceProfile(t.Context(), proj, "Webserver", "/app/")
			if err != nil {
				t.Fatal(err)
			}
			p := got.Profile
			if p.Name != "Webserver" || p.Path != "/app/" || !strings.HasPrefix(p.ID, "AIPA") || len(p.ID) != 21 ||
				p.UID == "" || !p.Created.Equal(now) || len(p.Roles) != 0 || len(got.Roles) != 0 {
				t.Fatalf("CreateInstanceProfile = %+v, want Webserver under /app/ with an AIPA id, created now, no role", got)
			}
			if want := "arn:vws:iam::" + proj + ":instance-profile/app/Webserver"; got.ARN != want {
				t.Fatalf("Arn = %q, want %q", got.ARN, want)
			}
			stored := storedProfile(t, b, "Webserver")
			if s := stored.Object; s.ID != p.ID || s.UID != p.UID || s.Path != p.Path || !s.Created.Equal(p.Created) {
				t.Fatalf("stored %+v, want it as returned %+v", s, p)
			}
			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				v, err := replica.api.GetInstanceProfile(t.Context(), proj, "webserver")
				if err != nil || v.Profile.ID != p.ID || v.ARN != got.ARN {
					t.Fatalf("GetInstanceProfile = %+v, %v, want the created profile", v, err)
				}
			}
			for _, name := range []string{"Webserver", "WEBSERVER"} {
				_, err := e.api.CreateInstanceProfile(t.Context(), proj, name, "/other/")
				wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			}
			if again := storedProfile(t, b, "Webserver"); again.Version != stored.Version || again.Object.Path != "/app/" {
				t.Fatalf("a refused create changed the profile: %+v", again)
			}
		})
	}
}

// TestCreateInstanceProfileDefaultPath: no path is "/", the AWS default,
// with the root ARN.
func TestCreateInstanceProfileDefaultPath(t *testing.T) {
	now := time.Now().UTC()
	e := newEnvOn(t, memstore.New(), &now)
	got, err := e.api.CreateInstanceProfile(t.Context(), proj, "web", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Profile.Path != "/" {
		t.Fatalf("Path = %q, want /", got.Profile.Path)
	}
	if want := "arn:vws:iam::" + proj + ":instance-profile/web"; got.ARN != want {
		t.Fatalf("Arn = %q, want %q", got.ARN, want)
	}
}

// TestCreateInstanceProfileConcurrent: of creates of one name in any case
// racing on two replicas exactly one succeeds and the rest are
// EntityAlreadyExists; the stored profile is the winner's. On both store
// backends.
func TestCreateInstanceProfileConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			names := []string{"web", "WEB", "Web"}
			ids := make([]string, 16)
			errs := make([]error, 16)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					v, err := replicas[i%2].api.CreateInstanceProfile(t.Context(), proj, names[i%len(names)], "/")
					ids[i], errs[i] = v.Profile.ID, err
				})
			}
			wg.Wait()
			won := ""
			for i, err := range errs {
				if err != nil {
					wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
					continue
				}
				if won != "" {
					t.Fatalf("two creates succeeded")
				}
				won = ids[i]
			}
			if won == "" {
				t.Fatal("no create succeeded")
			}
			if got := storedProfile(t, b, "web").Object.ID; got != won {
				t.Fatalf("stored id %q, want the winner's %q", got, won)
			}
		})
	}
}

// failingCreate fails every Create of kind k with err.
type failingCreate struct {
	store.Backend
	k   iam.Kind
	err error
}

func (f failingCreate) Create(ctx context.Context, k iam.Kind, key string, spec []byte) (string, error) {
	if k == f.k {
		return "", f.err
	}
	return f.Backend.Create(ctx, k, key, spec)
}

// TestCreateInstanceProfileErrors: a bad project, InstanceProfileName or
// Path is ValidationError and writes nothing, the AWS bounds are
// accepted, a canceled request writes nothing, and a store failure is
// InternalFailure, never success.
func TestCreateInstanceProfileErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	create := func(pid, name, path string) error {
		_, err := e.api.CreateInstanceProfile(ctx, pid, name, path)
		return err
	}
	for _, n := range []string{"", "a b", "a/b", "é", strings.Repeat("p", iam.MaxInstanceProfileNameLen+1)} {
		wantAWS(t, create(proj, n, "/"), codes.InvalidArgument, "ValidationError")
	}
	for _, path := range []string{"app", "/app", "app/", "//", "/a b/", "/é/", "/" + strings.Repeat("p", 511) + "/"} {
		wantAWS(t, create(proj, "web", path), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, create("Bad_Project", "web", "/"), codes.InvalidArgument, "ValidationError")
	profileGone(t, b, "web")

	long := strings.Repeat("p", iam.MaxInstanceProfileNameLen)
	if err := create(proj, long, "/"+strings.Repeat("q", 510)+"/"); err != nil {
		t.Fatalf("CreateInstanceProfile at the AWS bounds: %v", err)
	}
	if err := create(proj, "A+=,.@_-z9", "/a!~/b/"); err != nil {
		t.Fatalf("CreateInstanceProfile with the full alphabet: %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := e.api.CreateInstanceProfile(canceled, proj, "gone", "/"); err == nil {
		t.Fatal("a canceled create succeeded")
	}
	profileGone(t, b, "gone")

	fb := failingCreate{memstore.New(), iam.KindInstanceProfile, errors.New("backend down")}
	fe := newEnvOn(t, fb, &now)
	_, err := fe.api.CreateInstanceProfile(ctx, proj, "web", "/")
	wantAWS(t, err, codes.Internal, "InternalFailure")
}
