package grpcapi_test

import (
	"fmt"
	"maps"
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

// seedProfileAt stores instance profile name under path holding roles,
// as CreateInstanceProfile (#91) will.
func seedProfileAt(t *testing.T, b store.Backend, name, path string, roles ...string) {
	t.Helper()
	p := iam.InstanceProfile{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: name, Path: path,
		ID: iam.NewUniqueID("AIPA"), Created: time.Now().UTC(), Roles: roles,
	}
	if _, err := store.Create(t.Context(), store.Scoped(b, proj), p); err != nil {
		t.Fatal(err)
	}
}

// listedNames returns the names of a listing's profiles, in order.
func listedNames(pg grpcapi.InstanceProfileListing) []string {
	out := make([]string, 0, len(pg.Profiles))
	for _, p := range pg.Profiles {
		out = append(out, p.Name)
	}
	return out
}

// listEvery pages through ListInstanceProfiles with prefix and maxItems
// and returns every listed name and the number of pages.
func listEvery(t *testing.T, e *env, prefix string, maxItems int) ([]string, int) {
	t.Helper()
	var names []string
	marker := ""
	for pages := 1; ; pages++ {
		pg, err := e.api.ListInstanceProfiles(t.Context(), proj, prefix, marker, maxItems)
		if err != nil {
			t.Fatal(err)
		}
		if len(pg.Profiles) > maxItems {
			t.Fatalf("page %d has %d profiles, more than MaxItems %d", pages, len(pg.Profiles), maxItems)
		}
		names = append(names, listedNames(pg)...)
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

// TestListInstanceProfiles: every profile of the project is listed by
// default, ordered by case-folded name, each as stored with the stored
// roles it names; PathPrefix filters case-sensitively by path; another
// replica sees the same, and listing writes nothing. On both store
// backends.
func TestListInstanceProfiles(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			seedRole(t, e, "Other")
			seedRole(t, e, "Unused")
			seedProfileAt(t, b, "web", "/app/", "s3access")
			seedProfileAt(t, b, "Batch", "/app/batch/", "Other")
			seedProfileAt(t, b, "api", "/")
			seedProfileAt(t, b, "root", "")
			seedProfileAt(t, b, "stale", "/app/", "Gone")
			before := storedProfile(t, b, "web")

			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				for _, prefix := range []string{"", "/"} {
					pg, err := replica.api.ListInstanceProfiles(t.Context(), proj, prefix, "", 0)
					if err != nil {
						t.Fatal(err)
					}
					want := []string{"api", "Batch", "root", "stale", "web"}
					if got := listedNames(pg); !slices.Equal(got, want) {
						t.Fatalf("PathPrefix %q: profiles = %q, want %q", prefix, got, want)
					}
					if pg.IsTruncated || pg.Marker != "" {
						t.Fatalf("IsTruncated = %v, Marker = %q, want a complete page", pg.IsTruncated, pg.Marker)
					}
					if p := pg.Profiles[4]; p.ID != before.Object.ID || p.Path != "/app/" ||
						!slices.Equal(p.Roles, []string{"s3access"}) {
						t.Fatalf("web profile = %+v, want it as stored %+v", p, before.Object)
					}
					keys := slices.Sorted(maps.Keys(pg.Roles))
					if !slices.Equal(keys, []string{"other", "s3access"}) {
						t.Fatalf("Roles keys = %q, want [other s3access] (no unused or deleted role)", keys)
					}
					if r := pg.Roles["s3access"]; r.Name != "S3Access" || r.UID == "" {
						t.Fatalf("Roles[s3access] = %+v, want S3Access as stored", r)
					}
				}
			}
			for _, tc := range []struct {
				prefix string
				want   []string
			}{
				{"/app/", []string{"Batch", "stale", "web"}},
				{"/app/batch/", []string{"Batch"}},
				{"/ap", []string{"Batch", "stale", "web"}},
				{"/APP/", nil},
				{"/none/", nil},
			} {
				pg, err := e.api.ListInstanceProfiles(t.Context(), proj, tc.prefix, "", 0)
				if err != nil {
					t.Fatal(err)
				}
				if got := listedNames(pg); !slices.Equal(got, tc.want) {
					t.Fatalf("PathPrefix %q: profiles = %q, want %q", tc.prefix, got, tc.want)
				}
				if pg.IsTruncated || pg.Marker != "" {
					t.Fatalf("PathPrefix %q: IsTruncated = %v, Marker = %q, want complete", tc.prefix,
						pg.IsTruncated, pg.Marker)
				}
			}
			if got := storedProfile(t, b, "web"); got.Version != before.Version {
				t.Fatalf("listing wrote the profile: version %q, want %q", got.Version, before.Version)
			}
		})
	}
}

// TestListInstanceProfilesEmpty: a project without profiles is an empty,
// complete page with no roles, not an error.
func TestListInstanceProfilesEmpty(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedRole(t, e, "Lonely")
	pg, err := e.api.ListInstanceProfiles(t.Context(), proj, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Profiles) != 0 || len(pg.Roles) != 0 || pg.IsTruncated || pg.Marker != "" {
		t.Fatalf("page = %+v, want empty and complete", pg)
	}
}

// TestListInstanceProfilesPages: MaxItems bounds each page of the
// profiles under PathPrefix, IsTruncated and Marker continue it, every
// matching profile is listed once in order for any page size, and 1000
// is accepted. On both store backends.
func TestListInstanceProfilesPages(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			var want []string
			for i := range 5 {
				name := fmt.Sprintf("p%d", i)
				seedProfileAt(t, b, name, "/app/")
				seedProfileAt(t, b, fmt.Sprintf("q%d", i), "/other/")
				want = append(want, name)
			}
			for _, tc := range []struct{ maxItems, pages int }{{1, 5}, {2, 3}, {4, 2}, {5, 1}, {1000, 1}} {
				got, pages := listEvery(t, e, "/app/", tc.maxItems)
				if !slices.Equal(got, want) || pages != tc.pages {
					t.Fatalf("MaxItems %d: %q in %d pages, want %q in %d", tc.maxItems, got, pages, want, tc.pages)
				}
			}
			if got, _ := listEvery(t, e, "", 3); len(got) != 10 {
				t.Fatalf("every profile: %q, want 10", got)
			}
		})
	}
}

// TestListInstanceProfilesDefaultPage: without MaxItems a page holds 100
// profiles, as in AWS.
func TestListInstanceProfilesDefaultPage(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	for i := range grpcapi.DefaultInstanceProfilePageSize + 1 {
		seedProfileAt(t, b, fmt.Sprintf("p%03d", i), "/")
	}
	pg, err := e.api.ListInstanceProfiles(t.Context(), proj, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Profiles) != 100 || !pg.IsTruncated || pg.Marker == "" {
		t.Fatalf("default page: %d profiles, IsTruncated %v, Marker %q; want 100, true, set",
			len(pg.Profiles), pg.IsTruncated, pg.Marker)
	}
	next, err := e.api.ListInstanceProfiles(t.Context(), proj, "", pg.Marker, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := listedNames(next); len(got) != 1 || got[0] != "p100" || next.IsTruncated {
		t.Fatalf("second page = %q (IsTruncated %v), want [p100] complete", got, next.IsTruncated)
	}
}

// TestListInstanceProfilesChangesBetweenPages: a marker continues after
// the last listed name, so a profile deleted or added before it does not
// shift the listing: every profile that exists for the whole listing is
// returned once, and one added after the marker is seen.
func TestListInstanceProfilesChangesBetweenPages(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	for _, n := range []string{"a", "b", "c", "d"} {
		seedProfileAt(t, b, n, "/")
	}
	pg, err := e.api.ListInstanceProfiles(t.Context(), proj, "", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := listedNames(pg); !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("first page = %q, want [a b]", got)
	}
	a := storedProfile(t, b, "a")
	if err := store.Delete[iam.InstanceProfile](t.Context(), store.Scoped(b, proj), "a", a.Version); err != nil {
		t.Fatal(err)
	}
	seedProfileAt(t, b, "AA", "/")
	seedProfileAt(t, b, "e", "/")
	next, err := e.api.ListInstanceProfiles(t.Context(), proj, "", pg.Marker, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := listedNames(next); !slices.Equal(got, []string{"c", "d"}) || !next.IsTruncated {
		t.Fatalf("second page = %q (IsTruncated %v), want [c d] truncated", got, next.IsTruncated)
	}
	last, err := e.api.ListInstanceProfiles(t.Context(), proj, "", next.Marker, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := listedNames(last); !slices.Equal(got, []string{"e"}) || last.IsTruncated {
		t.Fatalf("last page = %q (IsTruncated %v), want [e] complete", got, last.IsTruncated)
	}
}

// TestListInstanceProfilesOrder: pages are ordered by case-folded name
// whatever order the backend lists in, so a marker continues
// deterministically.
func TestListInstanceProfilesOrder(t *testing.T) {
	b := reversedList{memstore.New()}
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	for _, n := range []string{"a", "B", "c", "D"} {
		seedProfileAt(t, b, n, "/")
	}
	got, pages := listEvery(t, e, "", 3)
	if want := []string{"a", "B", "c", "D"}; !slices.Equal(got, want) || pages != 2 {
		t.Fatalf("listed %q in %d pages, want %q in 2", got, pages, want)
	}
}

// TestListInstanceProfilesErrors: a bad PathPrefix, MaxItems, Marker
// character or project is ValidationError before any store access; a
// marker this service did not issue is InvalidInput; the PathPrefix
// bounds of AWS are accepted.
func TestListInstanceProfilesErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seedProfileAt(t, b, "web", "/")

	list := func(pid, prefix, marker string, maxItems int) error {
		_, err := e.api.ListInstanceProfiles(ctx, pid, prefix, marker, maxItems)
		return err
	}
	for _, p := range []string{"app/", "/a b/", "/\x00", "/é/", "/" + strings.Repeat("p", iam.MaxPathPrefixLen)} {
		wantAWS(t, list(proj, p, "", 0), codes.InvalidArgument, "ValidationError")
	}
	for _, p := range []string{"/" + strings.Repeat("p", iam.MaxPathPrefixLen-1), "/!~\x7f"} {
		if err := list(proj, p, "", 0); err != nil {
			t.Fatalf("PathPrefix %q: %v, want accepted", p, err)
		}
	}
	for _, n := range []int{-1, grpcapi.MaxInstanceProfilePageSize + 1} {
		wantAWS(t, list(proj, "", "", n), codes.InvalidArgument, "ValidationError")
	}
	for _, m := range []string{"\x00", "a\tb", "Ā"} {
		wantAWS(t, list(proj, "", m, 0), codes.InvalidArgument, "ValidationError")
	}
	// Not base64; base64 of a name with an upper-case letter or a slash,
	// which this service never issues.
	for _, m := range []string{"!!!", "V2Vi", "YS9i"} {
		wantAWS(t, list(proj, "", m, 0), codes.InvalidArgument, "InvalidInput")
	}
	wantAWS(t, list("Bad_Project", "", "", 0), codes.InvalidArgument, "ValidationError")
}
