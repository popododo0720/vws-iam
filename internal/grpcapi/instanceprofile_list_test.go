package grpcapi_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// profileNames returns the names of a page's profiles, in order.
func profileNames(pg grpcapi.InstanceProfilePage) []string {
	out := make([]string, 0, len(pg.Profiles))
	for _, p := range pg.Profiles {
		out = append(out, p.Name)
	}
	return out
}

// listAll pages through ListInstanceProfilesForRole with maxItems and
// returns every listed name and the number of pages.
func listAll(t *testing.T, e *env, role string, maxItems int) ([]string, int) {
	t.Helper()
	var names []string
	marker := ""
	for pages := 1; ; pages++ {
		pg, err := e.api.ListInstanceProfilesForRole(t.Context(), proj, role, marker, maxItems)
		if err != nil {
			t.Fatal(err)
		}
		if len(pg.Profiles) > maxItems {
			t.Fatalf("page %d has %d profiles, more than MaxItems %d", pages, len(pg.Profiles), maxItems)
		}
		names = append(names, profileNames(pg)...)
		if !pg.IsTruncated {
			if pg.Marker != "" {
				t.Fatalf("last page has Marker %q, want none", pg.Marker)
			}
			return names, pages
		}
		if pg.Marker == "" {
			t.Fatalf("page %d is truncated without a Marker", pages)
		}
		if pages > 100 {
			t.Fatalf("still truncated after %d pages; listed %q", pages, names)
		}
		marker = pg.Marker
	}
}

// TestListInstanceProfilesForRole: only the profiles that hold the role
// are listed, ordered by case-folded name, with the role as stored;
// names compare case-insensitively, another replica sees the same, and
// listing writes nothing. On both store backends.
func TestListInstanceProfilesForRole(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			seedRole(t, e, "Other")
			seedInstanceProfile(t, b, "web", "S3Access")
			seedInstanceProfile(t, b, "Batch", "s3access")
			seedInstanceProfile(t, b, "api", "S3ACCESS")
			seedInstanceProfile(t, b, "db", "Other")
			seedInstanceProfile(t, b, "empty")
			before := storedProfile(t, b, "web")

			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				pg, err := replica.api.ListInstanceProfilesForRole(t.Context(), proj, "s3access", "", 0)
				if err != nil {
					t.Fatal(err)
				}
				if got, want := profileNames(pg), []string{"api", "Batch", "web"}; !slices.Equal(got, want) {
					t.Fatalf("profiles = %q, want %q", got, want)
				}
				if pg.IsTruncated || pg.Marker != "" {
					t.Fatalf("IsTruncated = %v, Marker = %q, want a complete page", pg.IsTruncated, pg.Marker)
				}
				if pg.Role.Name != "S3Access" || pg.Role.UID == "" {
					t.Fatalf("Role = %+v, want S3Access as stored", pg.Role)
				}
				if p := pg.Profiles[2]; p.ID != before.Object.ID || p.Path != "/app/" || len(p.Roles) != 1 {
					t.Fatalf("web profile = %+v, want it as stored %+v", p, before.Object)
				}
			}
			if got := storedProfile(t, b, "web"); got.Version != before.Version {
				t.Fatalf("listing wrote the profile: version %q, want %q", got.Version, before.Version)
			}
		})
	}
}

// TestListInstanceProfilesForRoleEmpty: a role in no profile is an empty,
// complete page, not an error.
func TestListInstanceProfilesForRoleEmpty(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedRole(t, e, "Lonely")
	seedRole(t, e, "Busy")
	seedInstanceProfile(t, b, "web", "Busy")
	pg, err := e.api.ListInstanceProfilesForRole(t.Context(), proj, "Lonely", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Profiles) != 0 || pg.IsTruncated || pg.Marker != "" {
		t.Fatalf("page = %+v, want empty and complete", pg)
	}
}

// TestListInstanceProfilesForRolePages: MaxItems bounds each page,
// IsTruncated and Marker continue it, every profile is listed once in
// order for any page size, the default page is 100 and 1000 is accepted.
// On both store backends.
func TestListInstanceProfilesForRolePages(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "Shared")
			var want []string
			for i := range 5 {
				name := fmt.Sprintf("p%d", i)
				seedInstanceProfile(t, b, name, "Shared")
				want = append(want, name)
			}
			for _, tc := range []struct{ maxItems, pages int }{{1, 5}, {2, 3}, {4, 2}, {5, 1}, {1000, 1}} {
				got, pages := listAll(t, e, "Shared", tc.maxItems)
				if !slices.Equal(got, want) || pages != tc.pages {
					t.Fatalf("MaxItems %d: %q in %d pages, want %q in %d", tc.maxItems, got, pages, want, tc.pages)
				}
			}
		})
	}
}

// TestListInstanceProfilesForRoleDefaultPage: without MaxItems a page
// holds 100 profiles, as in AWS.
func TestListInstanceProfilesForRoleDefaultPage(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedRole(t, e, "Shared")
	for i := range grpcapi.DefaultInstanceProfilePageSize + 1 {
		seedInstanceProfile(t, b, fmt.Sprintf("p%03d", i), "Shared")
	}
	pg, err := e.api.ListInstanceProfilesForRole(t.Context(), proj, "Shared", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Profiles) != 100 || !pg.IsTruncated || pg.Marker == "" {
		t.Fatalf("default page: %d profiles, IsTruncated %v, Marker %q; want 100, true, set",
			len(pg.Profiles), pg.IsTruncated, pg.Marker)
	}
	next, err := e.api.ListInstanceProfilesForRole(t.Context(), proj, "Shared", pg.Marker, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := profileNames(next); len(got) != 1 || got[0] != "p100" || next.IsTruncated {
		t.Fatalf("second page = %q (IsTruncated %v), want [p100] complete", got, next.IsTruncated)
	}
}

// TestListInstanceProfilesForRoleChangesBetweenPages: a marker continues
// after the last listed name, so a profile deleted or added before it
// does not shift the listing: every profile that exists for the whole
// listing is returned once, and one added after the marker is seen.
func TestListInstanceProfilesForRoleChangesBetweenPages(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedRole(t, e, "Shared")
	for _, n := range []string{"a", "b", "c", "d"} {
		seedInstanceProfile(t, b, n, "Shared")
	}
	pg, err := e.api.ListInstanceProfilesForRole(t.Context(), proj, "Shared", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := profileNames(pg); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("first page = %q, want [a b]", got)
	}
	ps := store.Scoped(b, proj)
	a := storedProfile(t, b, "a")
	if err := store.Delete[iam.InstanceProfile](t.Context(), ps, "a", a.Version); err != nil {
		t.Fatal(err)
	}
	seedInstanceProfile(t, b, "AA", "Shared")
	seedInstanceProfile(t, b, "e", "Shared")
	next, err := e.api.ListInstanceProfilesForRole(t.Context(), proj, "Shared", pg.Marker, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := profileNames(next); !slices.Equal(got, []string{"c", "d"}) || !next.IsTruncated {
		t.Fatalf("second page = %q (IsTruncated %v), want [c d] truncated", got, next.IsTruncated)
	}
	last, err := e.api.ListInstanceProfilesForRole(t.Context(), proj, "Shared", next.Marker, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := profileNames(last); !slices.Equal(got, []string{"e"}) || last.IsTruncated {
		t.Fatalf("last page = %q (IsTruncated %v), want [e] complete", got, last.IsTruncated)
	}
}

// TestListInstanceProfilesForRoleErrors: an unknown role is NoSuchEntity,
// also when a profile still names it; a bad RoleName, MaxItems, Marker
// character or project is ValidationError before any store access; a
// marker this service did not issue is InvalidInput.
func TestListInstanceProfilesForRoleErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seedRole(t, e, "Known")
	seedInstanceProfile(t, b, "web", "Known")
	seedInstanceProfile(t, b, "stale", "Gone")

	list := func(pid, role, marker string, maxItems int) error {
		_, err := e.api.ListInstanceProfilesForRole(ctx, pid, role, marker, maxItems)
		return err
	}
	wantAWS(t, list(proj, "missing", "", 0), codes.NotFound, "NoSuchEntity")
	wantAWS(t, list(proj, "Gone", "", 0), codes.NotFound, "NoSuchEntity")
	for _, n := range []string{"", strings.Repeat("r", 65), "a/b", "a b", "rôle"} {
		wantAWS(t, list(proj, n, "", 0), codes.InvalidArgument, "ValidationError")
	}
	for _, n := range []int{-1, grpcapi.MaxInstanceProfilePageSize + 1} {
		wantAWS(t, list(proj, "Known", "", n), codes.InvalidArgument, "ValidationError")
	}
	for _, m := range []string{"\x00", "a\tb", "Ā"} {
		wantAWS(t, list(proj, "Known", m, 0), codes.InvalidArgument, "ValidationError")
	}
	// Not base64; base64 of a name with an upper-case letter or a slash,
	// which this service never issues.
	for _, m := range []string{"!!!", "V2Vi", "YS9i"} {
		wantAWS(t, list(proj, "Known", m, 0), codes.InvalidArgument, "InvalidInput")
	}
	wantAWS(t, list("Bad_Project", "Known", "", 0), codes.InvalidArgument, "ValidationError")
}

// reversedList lists every kind in the reverse of the backend's order, as
// a backend whose order is not by name might.
type reversedList struct{ store.Backend }

func (r reversedList) List(ctx context.Context, k iam.Kind) ([]store.Entry, error) {
	es, err := r.Backend.List(ctx, k)
	slices.Reverse(es)
	return es, err
}

// TestListInstanceProfilesForRoleOrder: pages are ordered by case-folded
// name whatever order the backend lists in, so a marker continues
// deterministically.
func TestListInstanceProfilesForRoleOrder(t *testing.T) {
	b := reversedList{memstore.New()}
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedRole(t, e, "Shared")
	for _, n := range []string{"a", "B", "c", "D"} {
		seedInstanceProfile(t, b, n, "Shared")
	}
	got, pages := listAll(t, e, "Shared", 3)
	if want := []string{"a", "B", "c", "D"}; !slices.Equal(got, want) || pages != 2 {
		t.Fatalf("listed %q in %d pages, want %q in 2", got, pages, want)
	}
}
