package grpcapi_test

import (
	"encoding/base64"
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

// detailNames flattens a page into kind/name strings: users, groups,
// roles, then policies.
func detailNames(pg grpcapi.AuthorizationDetails) []string {
	var out []string
	for _, d := range pg.Users {
		out = append(out, "user/"+d.User.Name)
	}
	for _, g := range pg.Groups {
		out = append(out, "group/"+g.Name)
	}
	for _, d := range pg.Roles {
		out = append(out, "role/"+d.Role.Name)
	}
	for _, d := range pg.Policies {
		out = append(out, "policy/"+d.Policy.Name)
	}
	return out
}

// detailsAll pages through GetAccountAuthorizationDetails with filter and
// maxItems and returns every listed entry and the number of pages;
// between pages it calls between, when set.
func detailsAll(
	t *testing.T, api *grpcapi.Server, filter []string, maxItems int, between func(page int),
) ([]string, int) {
	t.Helper()
	var names []string
	marker := ""
	for pages := 1; ; pages++ {
		pg, err := api.GetAccountAuthorizationDetails(t.Context(), proj, filter, marker, maxItems)
		if err != nil {
			t.Fatal(err)
		}
		got := detailNames(pg)
		if maxItems > 0 && len(got) > maxItems {
			t.Fatalf("page %d has %d entries, more than MaxItems %d", pages, len(got), maxItems)
		}
		names = append(names, got...)
		if !pg.IsTruncated {
			if pg.Marker != "" {
				t.Fatalf("last page has Marker %q, want none", pg.Marker)
			}
			return names, pages
		}
		if pg.Marker == "" {
			t.Fatalf("page %d is truncated without a Marker", pages)
		}
		if pages > 200 {
			t.Fatalf("still truncated after %d pages; listed %q", pages, names)
		}
		if between != nil {
			between(pages)
		}
		marker = pg.Marker
	}
}

// seedDetails stores, in proj of b, two managed policies (Dev with two
// versions), users alice (inline, attached, boundary, in two groups) and
// bob, groups Devs and admins, roles App (inline, attached, boundary, in
// a profile) and Bare, and instance profile web holding App.
func seedDetails(t *testing.T, b store.Backend) {
	t.Helper()
	sb := store.Scoped(b, proj)
	now := time.Now().UTC()
	dev, other := entPolicyARN("/team/", "Dev"), entPolicyARN("/", "Other")
	seedEntPolicy(t, b, proj, "/", "Other")
	meta := func() iam.Meta { return iam.Meta{UID: iam.NewUID(), Generation: 1} }
	for _, obj := range []iam.Object{
		iam.Policy{
			Meta: meta(), Name: "Dev", Path: "/team/", ID: iam.NewUniqueID("ANPA"), Created: now,
			Description: "dev access", DefaultVersion: "v2",
			Versions: []iam.PolicyVersion{
				{ID: "v1", Document: boundaryDoc, Created: now},
				{ID: "v2", Document: boundaryDoc, Created: now},
			},
		},
		iam.User{
			Meta: meta(), Name: "alice", Path: "/ops/", ID: iam.NewUniqueID("AIDA"), Created: now,
			AttachedPolicies: []string{dev, other}, PermissionsBoundary: dev,
			InlinePolicies: map[string]string{"inl": boundaryDoc},
		},
		iam.User{Meta: meta(), Name: "bob", ID: iam.NewUniqueID("AIDA"), Created: now},
		iam.Group{
			Meta: meta(), Name: "Devs", ID: iam.NewUniqueID("AGPA"), Created: now,
			Members: []string{"Alice"}, AttachedPolicies: []string{dev},
			InlinePolicies: map[string]string{"g": boundaryDoc},
		},
		iam.Group{Meta: meta(), Name: "admins", ID: iam.NewUniqueID("AGPA"), Created: now, Members: []string{"alice", "bob"}},
		iam.Role{
			Meta: meta(), Name: "App", ID: iam.NewUniqueID("AROA"), Created: now, AssumeRolePolicy: entTrust,
			AttachedPolicies: []string{dev}, PermissionsBoundary: other,
			InlinePolicies: map[string]string{"r": boundaryDoc},
		},
		iam.Role{Meta: meta(), Name: "Bare", ID: iam.NewUniqueID("AROA"), Created: now, AssumeRolePolicy: entTrust},
		iam.InstanceProfile{Meta: meta(), Name: "web", ID: iam.NewUniqueID("AIPA"), Created: now, Roles: []string{"app"}},
		iam.InstanceProfile{Meta: meta(), Name: "empty", ID: iam.NewUniqueID("AIPA"), Created: now},
	} {
		if _, err := store.Create(t.Context(), sb, obj); err != nil {
			t.Fatal(err)
		}
	}
	// Another project's entities never show.
	seedEntPolicy(t, b, "other", "/", "Elsewhere")
}

// TestGetAccountAuthorizationDetails: every user, group, role and
// customer managed policy of the project is listed in the AWS order with
// its relationships; Filter narrows the listing; another replica sees
// the same, and listing writes nothing. On both store backends.
func TestGetAccountAuthorizationDetails(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedDetails(t, b)
			dev, other := entPolicyARN("/team/", "Dev"), entPolicyARN("/", "Other")
			before, err := store.Get[iam.Policy](t.Context(), store.Scoped(b, proj), "Dev")
			if err != nil {
				t.Fatal(err)
			}
			all := []string{
				"user/alice", "user/bob", "group/admins", "group/Devs",
				"role/App", "role/Bare", "policy/Dev", "policy/Other",
			}
			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				pg, err := replica.api.GetAccountAuthorizationDetails(t.Context(), proj, nil, "", 0)
				if err != nil {
					t.Fatal(err)
				}
				if got := detailNames(pg); !slices.Equal(got, all) {
					t.Fatalf("entries = %q, want %q", got, all)
				}
				if pg.IsTruncated || pg.Marker != "" {
					t.Fatalf("IsTruncated = %v, Marker = %q, want a complete page", pg.IsTruncated, pg.Marker)
				}
				alice, bob := pg.Users[0], pg.Users[1]
				if !slices.Equal(alice.Groups, []string{"admins", "Devs"}) || !slices.Equal(bob.Groups, []string{"admins"}) {
					t.Fatalf("groups: alice %q, bob %q; want [admins Devs], [admins]", alice.Groups, bob.Groups)
				}
				if u := alice.User; u.Path != "/ops/" || u.PermissionsBoundary != dev ||
					!slices.Equal(u.AttachedPolicies, []string{dev, other}) || u.InlinePolicies["inl"] != boundaryDoc || u.ID == "" {
					t.Fatalf("alice = %+v", u)
				}
				if g := pg.Groups[1]; g.InlinePolicies["g"] != boundaryDoc || !slices.Equal(g.AttachedPolicies, []string{dev}) {
					t.Fatalf("Devs = %+v", g)
				}
				app, bare := pg.Roles[0], pg.Roles[1]
				if len(app.InstanceProfiles) != 1 || app.InstanceProfiles[0].Name != "web" || len(bare.InstanceProfiles) != 0 {
					t.Fatalf("profiles: App %+v, Bare %+v; want [web], none", app.InstanceProfiles, bare.InstanceProfiles)
				}
				if r, ok := pg.ProfileRoles["app"]; !ok || r.ID != app.Role.ID || len(pg.ProfileRoles) != 1 {
					t.Fatalf("ProfileRoles = %+v, want App only", pg.ProfileRoles)
				}
				if r := app.Role; r.AssumeRolePolicy != entTrust || r.PermissionsBoundary != other ||
					r.InlinePolicies["r"] != boundaryDoc {
					t.Fatalf("App = %+v", r)
				}
				d, o := pg.Policies[0], pg.Policies[1]
				// Dev: alice, Devs, App attach it; alice has it as boundary.
				// Other: alice attaches it; App has it as boundary.
				if d.AttachmentCount != 3 || d.BoundaryUsageCount != 1 || o.AttachmentCount != 1 || o.BoundaryUsageCount != 1 {
					t.Fatalf("counts: Dev %d/%d, Other %d/%d; want 3/1, 1/1",
						d.AttachmentCount, d.BoundaryUsageCount, o.AttachmentCount, o.BoundaryUsageCount)
				}
				if p := d.Policy; len(p.Versions) != 2 || p.DefaultVersion != "v2" || p.Description != "dev access" {
					t.Fatalf("Dev = %+v, want both versions, default v2", p)
				}
			}
			for _, tc := range []struct {
				filter []string
				want   []string
			}{
				{[]string{"User"}, []string{"user/alice", "user/bob"}},
				{[]string{"Group"}, []string{"group/admins", "group/Devs"}},
				{[]string{"Role"}, []string{"role/App", "role/Bare"}},
				{[]string{"LocalManagedPolicy"}, []string{"policy/Dev", "policy/Other"}},
				{[]string{"AWSManagedPolicy"}, nil},
				{[]string{"Role", "User", "Role"}, []string{"user/alice", "user/bob", "role/App", "role/Bare"}},
				{[]string{"AWSManagedPolicy", "Group"}, []string{"group/admins", "group/Devs"}},
			} {
				pg, err := e.api.GetAccountAuthorizationDetails(t.Context(), proj, tc.filter, "", 0)
				if err != nil {
					t.Fatal(err)
				}
				if got := detailNames(pg); !slices.Equal(got, tc.want) {
					t.Fatalf("filter %q: entries = %q, want %q", tc.filter, got, tc.want)
				}
			}
			// Group memberships and policy counts do not depend on Filter.
			pg, err := e.api.GetAccountAuthorizationDetails(t.Context(), proj, []string{"User"}, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			if got := pg.Users[0].Groups; len(got) != 2 {
				t.Fatalf("filter User: alice groups = %q, want 2", got)
			}
			pg, err = e.api.GetAccountAuthorizationDetails(t.Context(), proj, []string{"LocalManagedPolicy"}, "", 0)
			if err != nil {
				t.Fatal(err)
			}
			if n := pg.Policies[0].AttachmentCount; n != 3 {
				t.Fatalf("filter LocalManagedPolicy: Dev attached %d times, want 3", n)
			}
			after, err := store.Get[iam.Policy](t.Context(), store.Scoped(b, proj), "Dev")
			if err != nil || after.Version != before.Version {
				t.Fatalf("policy version %q -> %q (err %v), want unchanged", before.Version, after.Version, err)
			}
		})
	}
}

// TestGetAccountAuthorizationDetailsEmpty: a project with nothing stored
// is one empty, complete page.
func TestGetAccountAuthorizationDetailsEmpty(t *testing.T) {
	now := time.Now().UTC()
	e := newEnvOn(t, memstore.New(), &now)
	pg, err := e.api.GetAccountAuthorizationDetails(t.Context(), proj, nil, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := detailNames(pg); got != nil || pg.IsTruncated || pg.Marker != "" {
		t.Fatalf("page = %q, truncated %v, marker %q; want empty", got, pg.IsTruncated, pg.Marker)
	}
}

// TestGetAccountAuthorizationDetailsPages: any page size returns every
// entry once, in order, across kinds; the default page is 100.
func TestGetAccountAuthorizationDetailsPages(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedDetails(t, b)
			want, _ := detailsAll(t, e.api, nil, 0, nil)
			if len(want) != 8 {
				t.Fatalf("listed %q, want 8 entries", want)
			}
			for _, n := range []int{1, 2, 3, 7, 8, grpcapi.MaxListPageSize} {
				got, pages := detailsAll(t, e.api, nil, n, nil)
				if !slices.Equal(got, want) {
					t.Fatalf("MaxItems %d: listed %q, want %q", n, got, want)
				}
				if wantPages := (len(want) + n - 1) / n; pages != wantPages {
					t.Fatalf("MaxItems %d: %d pages, want %d", n, pages, wantPages)
				}
			}
		})
	}
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	for i := range 101 {
		seedEntPolicy(t, b, proj, "/", fmt.Sprintf("p%03d", i))
	}
	pg, err := e.api.GetAccountAuthorizationDetails(t.Context(), proj, nil, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pg.Policies) != grpcapi.DefaultListPageSize || !pg.IsTruncated {
		t.Fatalf("default page: %d policies, truncated %v; want 100, true", len(pg.Policies), pg.IsTruncated)
	}
}

// TestGetAccountAuthorizationDetailsChangesBetweenPages: entries created
// or deleted between pages do not shift the listing; every entry that
// exists for the whole listing is returned once.
func TestGetAccountAuthorizationDetailsChangesBetweenPages(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedDetails(t, b)
	sb := store.Scoped(b, proj)
	got, _ := detailsAll(t, e.api, nil, 2, func(page int) {
		if page != 1 {
			return
		}
		// After page 1 (alice, bob): drop a listed user, add one before
		// the marker and one after it.
		v, err := store.Get[iam.User](t.Context(), sb, "bob")
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Delete[iam.User](t.Context(), sb, "bob", v.Version); err != nil {
			t.Fatal(err)
		}
		for _, n := range []string{"aaron", "zed"} {
			u := iam.User{Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: n, ID: iam.NewUniqueID("AIDA"), Created: now}
			if _, err := store.Create(t.Context(), sb, u); err != nil {
				t.Fatal(err)
			}
		}
	})
	want := []string{
		"user/alice", "user/bob", "user/zed", "group/admins", "group/Devs",
		"role/App", "role/Bare", "policy/Dev", "policy/Other",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
}

// TestGetAccountAuthorizationDetailsRenaming: a user in a rename is
// listed once.
func TestGetAccountAuthorizationDetailsRenaming(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	sb := store.Scoped(b, proj)
	for _, u := range []iam.User{
		{Name: "old", RenameState: iam.RenameState{RenameTo: "new", RenameStarted: now}},
		{Name: "new", RenameState: iam.RenameState{RenamedFrom: "old", RenameStarted: now}},
	} {
		u.Meta = iam.Meta{UID: iam.NewUID(), Generation: 1}
		u.ID, u.Created = iam.NewUniqueID("AIDA"), now
		if _, err := store.CreateMarked(t.Context(), sb, u); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := detailsAll(t, e.api, nil, 0, nil)
	if want := []string{"user/old"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
}

// TestGetAccountAuthorizationDetailsErrors: enum, range and pattern faults
// are ValidationError, a forged marker InvalidInput, and a store failure
// ServiceFailure.
func TestGetAccountAuthorizationDetailsErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedDetails(t, b)
	get := func(pid string, filter []string, marker string, maxItems int) error {
		_, err := e.api.GetAccountAuthorizationDetails(t.Context(), pid, filter, marker, maxItems)
		return err
	}
	for _, f := range [][]string{{"user"}, {"Users"}, {" User"}, {"User", ""}, {"Policy"}} {
		wantAWS(t, get(proj, f, "", 0), codes.InvalidArgument, "ValidationError")
	}
	for _, n := range []int{-1, grpcapi.MaxListPageSize + 1} {
		wantAWS(t, get(proj, nil, "", n), codes.InvalidArgument, "ValidationError")
	}
	for _, m := range []string{"\x00", "a\tb", "Ā"} {
		wantAWS(t, get(proj, nil, m, 0), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, get("Bad_Project", nil, "", 0), codes.InvalidArgument, "ValidationError")
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, m := range []string{
		"!!!", enc("x:alice"), enc("1:Alice"), enc("1:a/b"), enc("alice"), enc("2:"), enc("4:" + strings.Repeat("p", 129)),
	} {
		wantAWS(t, get(proj, nil, m, 0), codes.InvalidArgument, "InvalidInput")
	}
	// A marker from another kind's listing is accepted and continues.
	if err := get(proj, nil, enc("3:app"), 0); err != nil {
		t.Fatalf("role marker: %v", err)
	}
	for _, k := range []iam.Kind{iam.KindUser, iam.KindGroup, iam.KindRole, iam.KindInstanceProfile, iam.KindPolicy} {
		broken := newEnvOn(t, failingList{b, k, errors.New("backend exploded")}, &now)
		_, err := broken.api.GetAccountAuthorizationDetails(t.Context(), proj, nil, "", 0)
		wantAWS(t, err, codes.Internal, "ServiceFailure")
	}
}
