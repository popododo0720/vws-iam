package grpcapi_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// seedTaggedRole stores role name in project pid with tags and returns
// its stored version.
func seedTaggedRole(t *testing.T, b store.Backend, pid, name string, tags map[string]string) string {
	t.Helper()
	v, err := store.Create(t.Context(), store.Scoped(b, pid), iam.Role{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: name, ID: iam.NewUniqueID("AROA"),
		Created: time.Now().UTC(), AssumeRolePolicy: entTrust, Tags: tags,
	})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// roleTagKeys returns the keys of tags in order.
func roleTagKeys(tags []grpcapi.RoleTag) []string {
	keys := make([]string, 0, len(tags))
	for _, tg := range tags {
		keys = append(keys, tg.Key)
	}
	return keys
}

// listAllRoleTags pages through the role's tags n at a time and returns
// every tag and the number of pages.
func listAllRoleTags(t *testing.T, e *env, role string, n int) (map[string]string, int) {
	t.Helper()
	got := map[string]string{}
	marker, pages := "", 0
	for {
		page, err := e.api.ListRoleTags(t.Context(), proj, role, marker, n)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if len(page.Tags) > n {
			t.Fatalf("page %d has %d tags, MaxItems %d", pages, len(page.Tags), n)
		}
		for _, tg := range page.Tags {
			if _, dup := got[tg.Key]; dup {
				t.Fatalf("tag %q returned twice", tg.Key)
			}
			got[tg.Key] = tg.Value
		}
		if page.IsTruncated != (page.Marker != "") {
			t.Fatalf("page %d: IsTruncated %v with marker %q", pages, page.IsTruncated, page.Marker)
		}
		if !page.IsTruncated {
			return got, pages
		}
		marker = page.Marker
	}
}

// TestListRoleTags: a role's tags come back with their values, sorted by
// key (byte order, case significant), for the role name in any case; an
// untagged role is an empty page; another project's role of the same
// name is not mixed in; the call writes nothing. On both store backends.
func TestListRoleTags(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			tags := map[string]string{"env": "prod", "Team": "platform", "Owner": "ops", "a": "", "Cost Center": "12345"}
			version := seedTaggedRole(t, b, proj, "App", tags)
			seedTaggedRole(t, b, proj, "Plain", nil)
			seedTaggedRole(t, b, "other", "App", map[string]string{"elsewhere": "yes"})

			for _, name := range []string{"App", "app", "APP"} {
				page, err := e.api.ListRoleTags(ctx, proj, name, "", 0)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				want := []string{"Cost Center", "Owner", "Team", "a", "env"}
				if got := roleTagKeys(page.Tags); !slices.Equal(got, want) {
					t.Fatalf("%s: keys %v, want %v", name, got, want)
				}
				for _, tg := range page.Tags {
					if tg.Value != tags[tg.Key] {
						t.Fatalf("%s: tag %q = %q, want %q", name, tg.Key, tg.Value, tags[tg.Key])
					}
				}
				if page.IsTruncated || page.Marker != "" {
					t.Fatalf("%s: IsTruncated %v, Marker %q on a complete page", name, page.IsTruncated, page.Marker)
				}
			}

			page, err := e.api.ListRoleTags(ctx, proj, "Plain", "", 0)
			if err != nil {
				t.Fatal(err)
			}
			if len(page.Tags) != 0 || page.IsTruncated || page.Marker != "" {
				t.Fatalf("untagged role: %+v, want an empty page", page)
			}

			page, err = e.api.ListRoleTags(ctx, "other", "app", "", 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := roleTagKeys(page.Tags); !slices.Equal(got, []string{"elsewhere"}) {
				t.Fatalf("other project: keys %v, want [elsewhere]", got)
			}

			after, err := store.Get[iam.Role](ctx, store.Scoped(b, proj), "App")
			if err != nil {
				t.Fatal(err)
			}
			if after.Version != version {
				t.Fatalf("ListRoleTags wrote the role: version %q, want %q", after.Version, version)
			}
		})
	}
}

// TestListRoleTagsPages: MaxItems bounds every page, a truncated page
// sets IsTruncated and a Marker, and following the markers returns every
// tag exactly once. On both store backends.
func TestListRoleTagsPages(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			tags := map[string]string{}
			for i := range 7 {
				tags[fmt.Sprintf("key-%d", i)] = fmt.Sprintf("value-%d", i)
			}
			seedTaggedRole(t, b, proj, "App", tags)
			for n, wantPages := range map[int]int{1: 7, 2: 4, 3: 3, 7: 1, 1000: 1} {
				got, pages := listAllRoleTags(t, e, "App", n)
				if !maps.Equal(got, tags) {
					t.Fatalf("MaxItems %d: tags %v, want %v", n, got, tags)
				}
				if pages != wantPages {
					t.Fatalf("MaxItems %d: %d pages, want %d", n, pages, wantPages)
				}
			}
		})
	}
}

// TestListRoleTagsDefaultPage: MaxItems 0 is the AWS default of 100, so
// a role at the AWS limit of 50 tags lists in one page, while 49 truncates.
func TestListRoleTagsDefaultPage(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	tags := map[string]string{}
	for i := range iam.MaxRoleTags {
		tags[fmt.Sprintf("k%02d", i)] = "v"
	}
	seedTaggedRole(t, b, proj, "Full", tags)
	page, err := e.api.ListRoleTags(t.Context(), proj, "Full", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Tags) != iam.MaxRoleTags || page.IsTruncated {
		t.Fatalf("default page: %d tags, IsTruncated %v; want %d, false", len(page.Tags), page.IsTruncated, iam.MaxRoleTags)
	}
	page, err = e.api.ListRoleTags(t.Context(), proj, "Full", "", iam.MaxRoleTags-1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Tags) != iam.MaxRoleTags-1 || !page.IsTruncated || page.Marker == "" {
		t.Fatalf("MaxItems 49: %d tags, IsTruncated %v, Marker %q", len(page.Tags), page.IsTruncated, page.Marker)
	}
	last, err := e.api.ListRoleTags(t.Context(), proj, "Full", page.Marker, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := roleTagKeys(last.Tags); !slices.Equal(got, []string{"k49"}) || last.IsTruncated {
		t.Fatalf("after marker: keys %v, IsTruncated %v; want [k49], false", got, last.IsTruncated)
	}
}

// TestListRoleTagsChangesBetweenPages: a marker continues after the last
// key returned even when tags change in between: a tag removed or added
// before the marker does not shift the listing, one added after it is
// returned.
func TestListRoleTagsChangesBetweenPages(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seedTaggedRole(t, b, proj, "App", map[string]string{"b": "1", "d": "2", "f": "3", "h": "4"})
	first, err := e.api.ListRoleTags(ctx, proj, "App", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := roleTagKeys(first.Tags); !slices.Equal(got, []string{"b", "d"}) || !first.IsTruncated {
		t.Fatalf("first page %v, IsTruncated %v", got, first.IsTruncated)
	}
	sb := store.Scoped(b, proj)
	r, err := store.Get[iam.Role](ctx, sb, "App")
	if err != nil {
		t.Fatal(err)
	}
	r.Object.Tags = map[string]string{"a": "new", "d": "2", "e": "new", "f": "3", "h": "4"}
	if _, err := store.Update(ctx, sb, r.Object, r.Version); err != nil {
		t.Fatal(err)
	}
	second, err := e.api.ListRoleTags(ctx, proj, "App", first.Marker, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := roleTagKeys(second.Tags); !slices.Equal(got, []string{"e", "f"}) || !second.IsTruncated {
		t.Fatalf("second page %v, IsTruncated %v; want [e f], true", got, second.IsTruncated)
	}
	third, err := e.api.ListRoleTags(ctx, proj, "App", second.Marker, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := roleTagKeys(third.Tags); !slices.Equal(got, []string{"h"}) || third.IsTruncated || third.Marker != "" {
		t.Fatalf("third page %v, IsTruncated %v, Marker %q; want [h], false, empty", got, third.IsTruncated, third.Marker)
	}
}

// TestListRoleTagsErrors: request faults are ValidationError or (a
// marker not issued here) InvalidInput before any store access, the AWS
// bounds are accepted, an unknown role is NoSuchEntity with the AWS
// message, and a store failure is ServiceFailure without backend detail.
func TestListRoleTagsErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	seedTaggedRole(t, b, proj, "App", map[string]string{"k": "v"})
	broken := newEnvOn(t, failingGet{b, iam.KindRole, errors.New("backend exploded")}, &now)
	marker := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, tc := range []struct {
		name, pid, role, marker string
		maxItems                int
		aws                     string
	}{
		{"empty project", "", "App", "", 0, "ValidationError"},
		{"bad project", "Bad_Project", "App", "", 0, "ValidationError"},
		{"empty role", proj, "", "", 0, "ValidationError"},
		{"role too long", proj, strings.Repeat("r", 65), "", 0, "ValidationError"},
		{"role bad character", proj, "app/role", "", 0, "ValidationError"},
		{"maxItems negative", proj, "App", "", -1, "ValidationError"},
		{"maxItems too large", proj, "App", "", 1001, "ValidationError"},
		{"marker control character", proj, "App", "a\x01", 0, "ValidationError"},
		{"marker outside latin-1", proj, "App", "a\u0100", 0, "ValidationError"},
		{"marker not base64", proj, "App", "!!!", 0, "InvalidInput"},
		{"marker reserved key", proj, "App", marker("aws:k"), 0, "InvalidInput"},
		{"marker empty key", proj, "App", marker("\x00"), 0, "InvalidInput"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page, err := broken.api.ListRoleTags(t.Context(), tc.pid, tc.role, tc.marker, tc.maxItems)
			wantAWS(t, err, codes.InvalidArgument, tc.aws)
			if len(page.Tags) != 0 {
				t.Fatalf("tags %v with an error", page.Tags)
			}
		})
	}

	e := newEnvOn(t, b, &now)
	for _, role := range []string{"Missing", strings.Repeat("r", 64)} {
		_, err := e.api.ListRoleTags(t.Context(), proj, role, "", 1000)
		wantAWS(t, err, codes.NotFound, "NoSuchEntity")
		if want := "The role with name " + role + " cannot be found."; status.Convert(err).Message() != want {
			t.Fatalf("message %q, want %q", status.Convert(err).Message(), want)
		}
	}
	if _, err := e.api.ListRoleTags(t.Context(), proj, "App", "", 1); err != nil {
		t.Fatalf("MaxItems 1 rejected: %v", err)
	}

	page, err := broken.api.ListRoleTags(t.Context(), proj, "App", "", 0)
	wantAWS(t, err, codes.Internal, "ServiceFailure")
	if len(page.Tags) != 0 || strings.Contains(err.Error(), "backend exploded") {
		t.Fatalf("tags %v, error %v; want no tags and no backend detail", page.Tags, err)
	}
}
