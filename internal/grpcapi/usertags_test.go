package grpcapi_test

import (
	"context"
	"maps"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestTagUser: tags are stored with the user, for the name in any case, a
// value is overwritten, a key repeated in one request keeps its last value,
// and the user keeps its id; a repeat on another replica writes nothing. On
// both store backends.
func TestTagUser(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			e.createUser(t, t.Context(), "Tagged")
			before := storedUser(t, b, "Tagged").Object

			err := e.api.TagUser(t.Context(), proj, "tagged",
				[]*iamv1.Tag{samlTag("team", "a"), samlTag("Env", "dev"), samlTag("team", "b"), samlTag("env", "")})
			if err != nil {
				t.Fatal(err)
			}
			got := storedUser(t, b, "Tagged")
			want := map[string]string{"team": "b", "Env": "dev", "env": ""}
			if !maps.Equal(got.Object.Tags, want) {
				t.Fatalf("tags %v, want %v", got.Object.Tags, want)
			}
			if got.Object.ID != before.ID || got.Object.UID != before.UID || got.Object.Generation != before.Generation+1 {
				t.Fatalf("user after tag: %+v, want id kept and generation moved", got.Object)
			}

			if err := newEnvOn(t, b, &now).api.TagUser(t.Context(), proj, "Tagged",
				[]*iamv1.Tag{samlTag("Env", "dev")}); err != nil {
				t.Fatalf("repeat on another replica: %v", err)
			}
			if again := storedUser(t, b, "Tagged"); again.Version != got.Version {
				t.Fatalf("repeat wrote the user: version %q, want %q", again.Version, got.Version)
			}

			if err := e.api.TagUser(t.Context(), proj, "Tagged", []*iamv1.Tag{samlTag("Env", "prod")}); err != nil {
				t.Fatal(err)
			}
			want["Env"] = "prod"
			if tags := storedUser(t, b, "Tagged").Object.Tags; !maps.Equal(tags, want) {
				t.Fatalf("tags after overwrite %v, want %v", tags, want)
			}
		})
	}
}

// TestTagUserErrors: request faults are refused before any store access, an
// unknown user is NoSuchEntity, a user being renamed keeps its tags, a user
// is never left with more than 50 tags, and a canceled request writes
// nothing.
func TestTagUserErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	one := []*iamv1.Tag{samlTag("k", "v")}

	wantAWS(t, e.api.TagUser(ctx, proj, "missing", one), codes.NotFound, "NoSuchEntity")
	for _, n := range []string{"", strings.Repeat("u", 65), "a/b", "üser"} {
		wantAWS(t, e.api.TagUser(ctx, proj, n, one), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, e.api.TagUser(ctx, "Bad_Project", "u", one), codes.InvalidArgument, "ValidationError")
	wantAWS(t, e.api.TagUser(ctx, proj, "missing", nil), codes.InvalidArgument, "ValidationError")
	wantAWS(t, e.api.TagUser(ctx, proj, "missing", userTags(0, iam.MaxUserTags+1)), codes.InvalidArgument,
		"ValidationError")
	bad := []*iamv1.Tag{
		samlTag("", "v"), samlTag("bad#key", "v"), samlTag("aws:k", "v"),
		samlTag("k", strings.Repeat("v", iam.MaxTagValueLen+1)),
	}
	for _, bad := range bad {
		wantAWS(t, e.api.TagUser(ctx, proj, "missing", []*iamv1.Tag{bad}), codes.InvalidArgument, "InvalidInput")
	}

	renaming := iam.User{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: "moving", ID: iam.NewUniqueID("AIDA"),
		Created: now, RenameState: iam.RenameState{RenameTo: "moved", RenameStarted: now},
	}
	if _, err := store.CreateMarked(ctx, store.Scoped(b, proj), renaming); err != nil {
		t.Fatal(err)
	}
	wantAWS(t, e.api.TagUser(ctx, proj, "moving", one), codes.Aborted, "ConcurrentModification")
	if got := storedUser(t, b, "moving"); len(got.Object.Tags) != 0 {
		t.Fatalf("renaming user tags = %v, want none", got.Object.Tags)
	}

	e.createUser(t, ctx, "full")
	if err := e.api.TagUser(ctx, proj, "full", userTags(0, iam.MaxUserTags-1)); err != nil {
		t.Fatal(err)
	}
	full := storedUser(t, b, "full")
	wantAWS(t, e.api.TagUser(ctx, proj, "full", userTags(iam.MaxUserTags-1, 2)), codes.ResourceExhausted,
		"LimitExceeded")
	if got := storedUser(t, b, "full"); got.Version != full.Version {
		t.Fatal("a refused tag over the limit wrote the user")
	}
	if err := e.api.TagUser(ctx, proj, "full", userTags(iam.MaxUserTags-2, 2)); err != nil {
		t.Fatalf("the 50th tag with an overwrite: %v", err)
	}
	if got := storedUser(t, b, "full"); len(got.Object.Tags) != iam.MaxUserTags {
		t.Fatalf("%d tags, want %d", len(got.Object.Tags), iam.MaxUserTags)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	last := storedUser(t, b, "full").Version
	if err := e.api.TagUser(canceled, proj, "full", []*iamv1.Tag{samlTag("k0", "new")}); err == nil {
		t.Fatal("a canceled request succeeded")
	}
	if got := storedUser(t, b, "full"); got.Version != last {
		t.Fatal("a canceled request wrote the user")
	}
}

// TestTagUserConcurrent: tag requests racing on two replicas all succeed
// and every tag is kept. Eight writers lose at most seven races each, within
// the store.Mutate attempts. On both store backends.
func TestTagUserConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			replicas[0].createUser(t, t.Context(), "racer")
			var wg sync.WaitGroup
			errs := make([]error, 8)
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.TagUser(t.Context(), proj, "racer", userTags(i, 1))
				})
			}
			wg.Wait()
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			if got := storedUser(t, b, "racer").Object.Tags; len(got) != len(errs) {
				t.Fatalf("tags after race %v, want %d", got, len(errs))
			}
		})
	}
}

// userTags is n tags k<from> to k<from+n-1>, each with value v.
func userTags(from, n int) []*iamv1.Tag {
	tags := make([]*iamv1.Tag, n)
	for i := range n {
		tags[i] = samlTag("k"+strconv.Itoa(from+i), "v")
	}
	return tags
}
