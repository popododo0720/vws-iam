package grpcapi_test

import (
	"context"
	"errors"
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

// seedAlias stores account alias name in project pid and points its
// claim at it, as CreateAccountAlias does.
func seedAlias(t *testing.T, b store.Backend, pid, name string) {
	t.Helper()
	a := iam.AccountAlias{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: name, Created: time.Now().UTC()}
	if _, err := store.Create(t.Context(), store.Scoped(b, pid), a); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(t.Context(), b, iam.AccountAliasClaim{Name: name, Project: pid, UID: a.UID}); err != nil {
		t.Fatal(err)
	}
}

// listAllAliases pages through ListAccountAliases with maxItems and
// returns every listed alias and the number of pages.
func listAllAliases(t *testing.T, e *env, maxItems int) ([]string, int) {
	t.Helper()
	var names []string
	marker := ""
	for pages := 1; ; pages++ {
		pg, err := e.api.ListAccountAliases(t.Context(), proj, marker, maxItems)
		if err != nil {
			t.Fatal(err)
		}
		if len(pg.Aliases) > maxItems {
			t.Fatalf("page %d has %d aliases, more than MaxItems %d", pages, len(pg.Aliases), maxItems)
		}
		names = append(names, pg.Aliases...)
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

// TestListAccountAliases: the project's alias is listed as stored on a
// complete page, another project's alias is not, another replica sees
// the same, and listing writes nothing. On both store backends.
func TestListAccountAliases(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedAlias(t, b, proj, "example-corporation")
			seedAlias(t, b, "other", "other-corp")
			before, err := store.Get[iam.AccountAlias](t.Context(), store.Scoped(b, proj), "example-corporation")
			if err != nil {
				t.Fatal(err)
			}
			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				pg, err := replica.api.ListAccountAliases(t.Context(), proj, "", 0)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(pg.Aliases, []string{"example-corporation"}) || pg.IsTruncated || pg.Marker != "" {
					t.Fatalf("page = %+v, want [example-corporation] complete", pg)
				}
			}
			after, err := store.Get[iam.AccountAlias](t.Context(), store.Scoped(b, proj), "example-corporation")
			if err != nil {
				t.Fatal(err)
			}
			if after.Version != before.Version {
				t.Fatalf("listing wrote the alias: version %q, want %q", after.Version, before.Version)
			}
		})
	}
}

// TestListAccountAliasesEmpty: a project without an alias is an empty,
// complete page, not an error, as AWS returns for an account without one.
func TestListAccountAliasesEmpty(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedAlias(t, b, "other", "other-corp")
	for _, n := range []int{0, 1, grpcapi.MaxListPageSize} {
		pg, err := e.api.ListAccountAliases(t.Context(), proj, "", n)
		if err != nil {
			t.Fatal(err)
		}
		if len(pg.Aliases) != 0 || pg.IsTruncated || pg.Marker != "" {
			t.Fatalf("MaxItems %d: page = %+v, want empty and complete", n, pg)
		}
	}
}

// TestListAccountAliasesPages: even legacy duplicate records produce one
// complete page for every valid page size, including the default.
func TestListAccountAliasesPages(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			for i := range 5 {
				seedAlias(t, b, proj, fmt.Sprintf("alias-%d", i))
			}
			for _, size := range []int{1, 2, 4, 5, 1000} {
				got, pages := listAllAliases(t, e, size)
				if !slices.Equal(got, []string{"alias-4"}) || pages != 1 {
					t.Fatalf("MaxItems %d: %v in %d pages", size, got, pages)
				}
			}
			pg, err := e.api.ListAccountAliases(t.Context(), proj, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(pg.Aliases, []string{"alias-4"}) || pg.IsTruncated || pg.Marker != "" {
				t.Fatalf("default page %+v", pg)
			}
		})
	}
}

// TestListAccountAliasesChangesBetweenPages keeps markers issued before the
// singleton listing compatible, without resurrecting a replaced alias.
func TestListAccountAliasesChangesBetweenPages(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	for _, name := range []string{"aaa", "bbb", "ccc"} {
		seedAlias(t, b, proj, name)
	}
	pg, err := e.api.ListAccountAliases(t.Context(), proj, "Y2Nj", 1) // ccc
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Aliases) != 0 || pg.IsTruncated {
		t.Fatalf("replaced aliases leaked: %+v", pg)
	}
	seedAlias(t, b, proj, "ddd")
	pg, err = e.api.ListAccountAliases(t.Context(), proj, "Y2Nj", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(pg.Aliases, []string{"ddd"}) || pg.IsTruncated || pg.Marker != "" {
		t.Fatalf("new alias page %+v", pg)
	}
}

func TestListAccountAliasesHidesStoppedReplacement(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			sb := store.Scoped(b, proj)
			seedAlias(t, b, proj, "zzz-old")
			seedAlias(t, b, proj, "aaa-latest")
			seedAlias(t, b, "other", "other-corp")
			if _, err := store.Mutate(t.Context(), sb, "aaa-latest", func(a *iam.AccountAlias) error {
				a.Seq = 2
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			pending := iam.AccountAlias{
				Meta:    iam.Meta{UID: iam.NewUID(), Generation: 1},
				Name:    "pending-create",
				Created: now,
				Seq:     3,
			}
			if _, err := store.Create(t.Context(), sb, pending); err != nil {
				t.Fatal(err)
			}
			before, err := store.List[iam.AccountAlias](t.Context(), sb)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				e := newEnvOn(t, b, &now)
				if got := listedAliases(t, e, proj); !slices.Equal(got, []string{"aaa-latest"}) {
					t.Fatalf("listed %v", got)
				}
				if got := listedAliases(t, e, "other"); !slices.Equal(got, []string{"other-corp"}) {
					t.Fatalf("other listed %v", got)
				}
			}
			after, err := store.List[iam.AccountAlias](t.Context(), sb)
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != len(before) {
				t.Fatal("listing deleted a record")
			}
			for i, v := range before {
				if after[i].Version != v.Version {
					t.Fatal("listing modified a stored or live-create record")
				}
			}
		})
	}
}

// failingList fails every List of kind k with err.
type failingList struct {
	store.Backend
	k   iam.Kind
	err error
}

func (f failingList) List(ctx context.Context, k iam.Kind) ([]store.Entry, error) {
	if k == f.k {
		return nil, f.err
	}
	return f.Backend.List(ctx, k)
}

// TestListAccountAliasesErrors: a bad project, MaxItems or Marker is
// ValidationError before any store access, a marker this service did not
// issue is InvalidInput, and a store failure is an internal error (which
// console-api answers as ServiceFailure), never an empty page.
func TestListAccountAliasesErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	seedAlias(t, b, proj, "example-corp")

	list := func(pid, marker string, maxItems int) error {
		_, err := e.api.ListAccountAliases(ctx, pid, marker, maxItems)
		return err
	}
	wantAWS(t, list("Bad_Project", "", 0), codes.InvalidArgument, "ValidationError")
	for _, n := range []int{-1, grpcapi.MaxListPageSize + 1} {
		wantAWS(t, list(proj, "", n), codes.InvalidArgument, "ValidationError")
	}
	for _, m := range []string{"\x00", "a\tb", "Ā"} {
		wantAWS(t, list(proj, m, 0), codes.InvalidArgument, "ValidationError")
	}
	// Not base64; base64 of "Abc" (upper case), "a--b" and "ab" (too
	// short), which are not aliases this service issues markers for.
	for _, m := range []string{"!!!", "QWJj", "YS0tYg", "YWI"} {
		wantAWS(t, list(proj, m, 0), codes.InvalidArgument, "InvalidInput")
	}
	// An instance profile marker is not an alias marker: "web_1".
	wantAWS(t, list(proj, "d2ViXzE", 0), codes.InvalidArgument, "InvalidInput")
	for _, n := range []int{1, grpcapi.MaxListPageSize} {
		if err := list(proj, "", n); err != nil {
			t.Fatalf("MaxItems %d: %v, want accepted", n, err)
		}
	}

	fb := failingList{memstore.New(), iam.KindAccountAlias, errors.New("backend down")}
	fe := newEnvOn(t, fb, &now)
	_, err := fe.api.ListAccountAliases(ctx, proj, "", 0)
	wantAWS(t, err, codes.Internal, "InternalFailure")
	if strings.Contains(err.Error(), "backend down") {
		t.Fatalf("error %v leaks backend detail", err)
	}
}
