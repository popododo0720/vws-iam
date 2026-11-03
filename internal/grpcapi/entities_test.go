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

const entTrust = `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
	`"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}}`

// entPolicyARN is the ARN of managed policy name at path in proj.
func entPolicyARN(path, name string) string { return "arn:vws:iam::" + proj + ":policy" + path + name }

// seedEntPolicy stores managed policy name at path in pid.
func seedEntPolicy(t *testing.T, b store.Backend, pid, path, name string) {
	t.Helper()
	now := time.Now().UTC()
	p := iam.Policy{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: name, Path: path, ID: iam.NewUniqueID("ANPA"),
		Created: now, DefaultVersion: "v1",
		Versions: []iam.PolicyVersion{{ID: "v1", Document: boundaryDoc, Created: now}},
	}
	if _, err := store.Create(t.Context(), store.Scoped(b, pid), p); err != nil {
		t.Fatal(err)
	}
}

// entity describes a seeded user, group or role.
type entity struct {
	kind, name, path, boundary string
	attached                   []string
}

// seedEntity stores e in proj and returns its unique id.
func seedEntity(t *testing.T, b store.Backend, e entity) string {
	t.Helper()
	meta := iam.Meta{UID: iam.NewUID(), Generation: 1}
	now := time.Now().UTC()
	var obj iam.Object
	var id string
	switch e.kind {
	case "user":
		id = iam.NewUniqueID("AIDA")
		obj = iam.User{
			Meta: meta, Name: e.name, Path: e.path, ID: id, Created: now,
			AttachedPolicies: e.attached, PermissionsBoundary: e.boundary,
		}
	case "group":
		id = iam.NewUniqueID("AGPA")
		obj = iam.Group{Meta: meta, Name: e.name, Path: e.path, ID: id, Created: now, AttachedPolicies: e.attached}
	default:
		id = iam.NewUniqueID("AROA")
		obj = iam.Role{
			Meta: meta, Name: e.name, Path: e.path, ID: id, Created: now, AssumeRolePolicy: entTrust,
			AttachedPolicies: e.attached, PermissionsBoundary: e.boundary,
		}
	}
	if _, err := store.Create(t.Context(), store.Scoped(b, proj), obj); err != nil {
		t.Fatal(err)
	}
	return id
}

// entNames flattens a page into kind/name strings, groups, roles, users.
func entNames(pg grpcapi.PolicyEntities) []string {
	var out []string
	for _, e := range pg.PolicyGroups {
		out = append(out, "group/"+e.Name)
	}
	for _, e := range pg.PolicyRoles {
		out = append(out, "role/"+e.Name)
	}
	for _, e := range pg.PolicyUsers {
		out = append(out, "user/"+e.Name)
	}
	return out
}

// listEntitiesAll pages through ListEntitiesForPolicy for q with maxItems
// and returns every listed entity and the number of pages; between pages
// it calls between, when set.
func listEntitiesAll(
	t *testing.T, api *grpcapi.Server, q grpcapi.EntitiesQuery, between func(page int),
) ([]string, int) {
	t.Helper()
	var names []string
	for pages := 1; ; pages++ {
		pg, err := api.ListEntitiesForPolicy(t.Context(), proj, q)
		if err != nil {
			t.Fatal(err)
		}
		got := entNames(pg)
		if q.MaxItems > 0 && len(got) > q.MaxItems {
			t.Fatalf("page %d has %d entities, more than MaxItems %d", pages, len(got), q.MaxItems)
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
		q.Marker = pg.Marker
	}
}

// TestListEntitiesForPolicy: the users, groups and roles holding the
// policy as a permissions policy or boundary are listed with name and id;
// EntityFilter, PolicyUsageFilter and PathPrefix narrow the listing;
// another replica sees the same, and listing writes nothing. On both
// store backends.
func TestListEntitiesForPolicy(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			pol, other := entPolicyARN("/team/", "Dev"), entPolicyARN("/", "Other")
			seedEntPolicy(t, b, proj, "/team/", "Dev")
			seedEntPolicy(t, b, proj, "/", "Other")
			ids := map[string]string{}
			for _, en := range []entity{
				{kind: "user", name: "alice", attached: []string{other, pol}},
				{kind: "user", name: "Bob", path: "/ops/", boundary: pol},
				{kind: "user", name: "carol", attached: []string{other}, boundary: other},
				{kind: "user", name: "dave", path: "/ops/", attached: []string{pol}, boundary: pol},
				{kind: "group", name: "Devs", path: "/ops/", attached: []string{pol}},
				{kind: "group", name: "others", attached: []string{other}},
				{kind: "role", name: "Admin", path: "/svc/", attached: []string{pol}},
				{kind: "role", name: "bounded", boundary: pol},
				{kind: "role", name: "plain"},
			} {
				ids[en.kind+"/"+en.name] = seedEntity(t, b, en)
			}
			before, err := store.Get[iam.User](t.Context(), store.Scoped(b, proj), "alice")
			if err != nil {
				t.Fatal(err)
			}
			all := []string{"group/Devs", "role/Admin", "role/bounded", "user/alice", "user/Bob", "user/dave"}
			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				pg, err := replica.api.ListEntitiesForPolicy(t.Context(), proj, grpcapi.EntitiesQuery{PolicyARN: pol})
				if err != nil {
					t.Fatal(err)
				}
				if got := entNames(pg); !slices.Equal(got, all) {
					t.Fatalf("entities = %q, want %q", got, all)
				}
				if pg.IsTruncated || pg.Marker != "" {
					t.Fatalf("IsTruncated = %v, Marker = %q, want a complete page", pg.IsTruncated, pg.Marker)
				}
				for _, got := range [][]string{
					{"group/" + pg.PolicyGroups[0].Name, pg.PolicyGroups[0].ID},
					{"role/" + pg.PolicyRoles[1].Name, pg.PolicyRoles[1].ID},
					{"user/" + pg.PolicyUsers[1].Name, pg.PolicyUsers[1].ID},
				} {
					if ids[got[0]] != got[1] || got[1] == "" {
						t.Fatalf("%s id = %q, want %q", got[0], got[1], ids[got[0]])
					}
				}
			}
			for _, tc := range []struct {
				q    grpcapi.EntitiesQuery
				want []string
			}{
				{grpcapi.EntitiesQuery{EntityFilter: "User"}, []string{"user/alice", "user/Bob", "user/dave"}},
				{grpcapi.EntitiesQuery{EntityFilter: "Group"}, []string{"group/Devs"}},
				{grpcapi.EntitiesQuery{EntityFilter: "Role"}, []string{"role/Admin", "role/bounded"}},
				{grpcapi.EntitiesQuery{EntityFilter: "LocalManagedPolicy"}, nil},
				{grpcapi.EntitiesQuery{EntityFilter: "AWSManagedPolicy"}, nil},
				{
					grpcapi.EntitiesQuery{PolicyUsageFilter: "PermissionsPolicy"},
					[]string{"group/Devs", "role/Admin", "user/alice", "user/dave"},
				},
				{
					grpcapi.EntitiesQuery{PolicyUsageFilter: "PermissionsBoundary"},
					[]string{"role/bounded", "user/Bob", "user/dave"},
				},
				{grpcapi.EntitiesQuery{PathPrefix: "/"}, all},
				{grpcapi.EntitiesQuery{PathPrefix: "/ops/"}, []string{"group/Devs", "user/Bob", "user/dave"}},
				{grpcapi.EntitiesQuery{PathPrefix: "/OPS/"}, nil},
				{
					grpcapi.EntitiesQuery{PathPrefix: "/ops/", EntityFilter: "User", PolicyUsageFilter: "PermissionsPolicy"},
					[]string{"user/dave"},
				},
				{grpcapi.EntitiesQuery{PolicyARN: other}, []string{"group/others", "user/alice", "user/carol"}},
				{grpcapi.EntitiesQuery{PolicyARN: other, PolicyUsageFilter: "PermissionsBoundary"}, []string{"user/carol"}},
			} {
				if tc.q.PolicyARN == "" {
					tc.q.PolicyARN = pol
				}
				pg, err := e.api.ListEntitiesForPolicy(t.Context(), proj, tc.q)
				if err != nil {
					t.Fatalf("%+v: %v", tc.q, err)
				}
				if got := entNames(pg); !slices.Equal(got, tc.want) || pg.IsTruncated {
					t.Fatalf("%+v: entities = %q (truncated %v), want %q", tc.q, got, pg.IsTruncated, tc.want)
				}
			}
			after, err := store.Get[iam.User](t.Context(), store.Scoped(b, proj), "alice")
			if err != nil {
				t.Fatal(err)
			}
			if after.Version != before.Version {
				t.Fatalf("listing wrote alice: version %q, want %q", after.Version, before.Version)
			}
		})
	}
}

// TestListEntitiesForPolicyUnattached: a policy held by no entity is an
// empty, complete page, not an error.
func TestListEntitiesForPolicyUnattached(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedEntPolicy(t, b, proj, "/", "Lonely")
	seedEntity(t, b, entity{kind: "user", name: "alice"})
	q := grpcapi.EntitiesQuery{PolicyARN: entPolicyARN("/", "Lonely")}
	pg, err := e.api.ListEntitiesForPolicy(t.Context(), proj, q)
	if err != nil {
		t.Fatal(err)
	}
	if len(entNames(pg)) != 0 || pg.IsTruncated || pg.Marker != "" {
		t.Fatalf("page = %+v, want empty and complete", pg)
	}
}

// TestListEntitiesForPolicyPages: MaxItems bounds each page across groups,
// roles and users, and every entity is listed once in order for any page
// size, 1000 included. On both store backends, with a backend that lists
// in reverse order.
func TestListEntitiesForPolicyPages(t *testing.T) {
	backends := append(renameBackends, struct {
		name string
		open func() store.Backend
	}{"reversed", func() store.Backend { return reversedList{memstore.New()} }})
	for _, bk := range backends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			pol := entPolicyARN("/", "P")
			seedEntPolicy(t, b, proj, "/", "P")
			var want []string
			for _, en := range []entity{
				{kind: "group", name: "g-a"},
				{kind: "group", name: "G-b"},
				{kind: "role", name: "R-a"},
				{kind: "role", name: "r-b", boundary: pol},
				{kind: "user", name: "u-a"},
				{kind: "user", name: "U-b"},
				{kind: "user", name: "u-c", boundary: pol},
			} {
				if en.boundary == "" {
					en.attached = []string{pol}
				}
				seedEntity(t, b, en)
				want = append(want, en.kind+"/"+en.name)
			}
			seedEntity(t, b, entity{kind: "user", name: "noise"})
			for _, tc := range []struct{ maxItems, pages int }{{1, 7}, {2, 4}, {3, 3}, {6, 2}, {7, 1}, {1000, 1}} {
				got, pages := listEntitiesAll(t, e.api, grpcapi.EntitiesQuery{PolicyARN: pol, MaxItems: tc.maxItems}, nil)
				if !slices.Equal(got, want) || pages != tc.pages {
					t.Fatalf("MaxItems %d: %q in %d pages, want %q in %d", tc.maxItems, got, pages, want, tc.pages)
				}
			}
		})
	}
}

// TestListEntitiesForPolicyDefaultPage: without MaxItems a page holds 100
// entities, as in AWS.
func TestListEntitiesForPolicyDefaultPage(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	pol := entPolicyARN("/", "P")
	seedEntPolicy(t, b, proj, "/", "P")
	for i := range grpcapi.DefaultListPageSize + 1 {
		seedEntity(t, b, entity{kind: "user", name: fmt.Sprintf("u%03d", i), attached: []string{pol}})
	}
	pg, err := e.api.ListEntitiesForPolicy(t.Context(), proj, grpcapi.EntitiesQuery{PolicyARN: pol})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(pg.PolicyUsers); n != grpcapi.DefaultListPageSize || !pg.IsTruncated || pg.Marker == "" {
		t.Fatalf("default page: %d users, IsTruncated %v, Marker %q; want 100, true, set", n, pg.IsTruncated, pg.Marker)
	}
	got, _ := listEntitiesAll(t, e.api, grpcapi.EntitiesQuery{PolicyARN: pol}, nil)
	if len(got) != grpcapi.DefaultListPageSize+1 {
		t.Fatalf("listed %d users, want 101", len(got))
	}
}

// TestListEntitiesForPolicyChangesBetweenPages: entities created or
// deleted between pages do not shift the listing; every entity present
// for the whole listing is returned once.
func TestListEntitiesForPolicyChangesBetweenPages(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	pol := entPolicyARN("/", "P")
	seedEntPolicy(t, b, proj, "/", "P")
	for _, en := range []entity{
		{kind: "group", name: "g1"},
		{kind: "role", name: "r1"},
		{kind: "role", name: "r2"},
		{kind: "user", name: "u1"},
		{kind: "user", name: "u3"},
	} {
		en.attached = []string{pol}
		seedEntity(t, b, en)
	}
	sb := store.Scoped(b, proj)
	got, _ := listEntitiesAll(t, e.api, grpcapi.EntitiesQuery{PolicyARN: pol, MaxItems: 2}, func(page int) {
		if page != 1 {
			return
		}
		// After page 1 (g1, r1): drop a listed group, add one before the
		// marker and a user after it.
		if err := sb.Delete(t.Context(), iam.KindGroup, "g1", ""); err != nil {
			t.Fatal(err)
		}
		seedEntity(t, b, entity{kind: "group", name: "g0", attached: []string{pol}})
		seedEntity(t, b, entity{kind: "user", name: "u2", attached: []string{pol}})
	})
	if want := []string{"group/g1", "role/r1", "role/r2", "user/u1", "user/u2", "user/u3"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
}

// TestListEntitiesForPolicyRenaming: a user in a rename is listed once,
// under the name that counts until the rename finishes.
func TestListEntitiesForPolicyRenaming(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	pol := entPolicyARN("/", "P")
	seedEntPolicy(t, b, proj, "/", "P")
	sb := store.Scoped(b, proj)
	for _, u := range []iam.User{
		{Name: "old", RenameState: iam.RenameState{RenameTo: "new", RenameStarted: now}},
		{Name: "new", RenameState: iam.RenameState{RenamedFrom: "old", RenameStarted: now}},
	} {
		u.Meta = iam.Meta{UID: iam.NewUID(), Generation: 1}
		u.ID, u.Created, u.AttachedPolicies = iam.NewUniqueID("AIDA"), now, []string{pol}
		if _, err := store.CreateMarked(t.Context(), sb, u); err != nil {
			t.Fatal(err)
		}
	}
	got, _ := listEntitiesAll(t, e.api, grpcapi.EntitiesQuery{PolicyARN: pol}, nil)
	if want := []string{"user/old"}; !slices.Equal(got, want) {
		t.Fatalf("listed %q, want %q", got, want)
	}
}

// TestListEntitiesForPolicyErrors: length, pattern and enum faults are
// ValidationError, a malformed ARN or forged marker InvalidInput, an
// unknown policy NoSuchEntity and a store failure ServiceFailure.
func TestListEntitiesForPolicyErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	pol := entPolicyARN("/team/", "Dev")
	seedEntPolicy(t, b, proj, "/team/", "Dev")
	seedEntPolicy(t, b, "other", "/team/", "Dev")
	list := func(pid string, q grpcapi.EntitiesQuery) error {
		if q.PolicyARN == "" {
			q.PolicyARN = pol
		}
		_, err := e.api.ListEntitiesForPolicy(t.Context(), pid, q)
		return err
	}
	validation := []grpcapi.EntitiesQuery{
		{PolicyARN: "arn:vws:iam::a:p"},
		{PolicyARN: "arn:vws:iam::" + proj + ":policy/" + strings.Repeat("p", 2048)},
		{EntityFilter: "user"},
		{EntityFilter: "Users"},
		{EntityFilter: " User"},
		{PolicyUsageFilter: "permissionsPolicy"},
		{PolicyUsageFilter: "Boundary"},
		{PathPrefix: "ops/"},
		{PathPrefix: "/ops"},
		{PathPrefix: "//"},
		{PathPrefix: "/o ps/"},
		{PathPrefix: "/o\x7fps/"},
		{PathPrefix: "/" + strings.Repeat("p", 511) + "/"},
		{MaxItems: -1},
		{MaxItems: grpcapi.MaxListPageSize + 1},
		{Marker: "\x00"},
		{Marker: "a\tb"},
		{Marker: "Ā"},
	}
	for _, q := range validation {
		wantAWS(t, list(proj, q), codes.InvalidArgument, "ValidationError")
	}
	wantAWS(t, list("Bad_Project", grpcapi.EntitiesQuery{}), codes.InvalidArgument, "ValidationError")
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for _, q := range []grpcapi.EntitiesQuery{
		{PolicyARN: "arn:aws:iam::123456789012:policy/Dev"},
		{PolicyARN: "arn:vws:iam::" + proj + ":user/team/Dev"},
		{PolicyARN: "arn:vws:iam:::policy/team/Dev"},
		{Marker: "!!!"},
		{Marker: enc("x:alice")},
		{Marker: enc("u:Alice")},
		{Marker: enc("u:a/b")},
		{Marker: enc("alice")},
		{Marker: enc("g:")},
	} {
		wantAWS(t, list(proj, q), codes.InvalidArgument, "InvalidInput")
	}
	for _, arn := range []string{
		entPolicyARN("/team/", "Missing"),
		entPolicyARN("/", "Dev"),
		entPolicyARN("/TEAM/", "Dev"),
		"arn:vws:iam::other:policy/team/Dev",
		"arn:vws:iam::aws:policy/ReadOnlyAccess",
	} {
		wantAWS(t, list(proj, grpcapi.EntitiesQuery{PolicyARN: arn}), codes.NotFound, "NoSuchEntity")
	}
	for _, k := range []iam.Kind{iam.KindGroup, iam.KindRole, iam.KindUser} {
		broken := newEnvOn(t, failingList{b, k, errors.New("backend exploded")}, &now)
		_, err := broken.api.ListEntitiesForPolicy(t.Context(), proj, grpcapi.EntitiesQuery{PolicyARN: pol})
		wantAWS(t, err, codes.Internal, "ServiceFailure")
	}
}
