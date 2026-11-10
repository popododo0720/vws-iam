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
	"github.com/popododo0720/vws-iam/internal/store"
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

func listProfilesRPC(
	t *testing.T, e *env, req *iamv1.ListInstanceProfilesRequest,
) (*iamv1.ListInstanceProfilesResponse, error) {
	t.Helper()
	return e.profiles.ListInstanceProfiles(t.Context(), req)
}

// TestListInstanceProfilesRPC: InstanceProfileService.ListInstanceProfiles
// lists the profiles under path_prefix ordered by case-folded name, each
// exactly as GetInstanceProfile returns it (envelope, etag, path, ARN and
// stored roles, a deleted role's stale name left out); page_size bounds a
// page and next_page_token, set only on a truncated page, continues it
// until every profile is listed once. A second server on the same store
// gives the same answer, and listing writes nothing. On both store
// backends.
func TestListInstanceProfilesRPC(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			seedProfileAt(t, b, "web", "/app/", "s3access")
			seedProfileAt(t, b, "Batch", "/app/batch/")
			seedProfileAt(t, b, "stale", "/app/", "Gone")
			seedProfileAt(t, b, "api", "/")
			before := storedProfile(t, b, "web")

			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				got, err := listProfilesRPC(t, replica, &iamv1.ListInstanceProfilesRequest{
					Parent: parentName, PathPrefix: "/app/",
				})
				if err != nil {
					t.Fatal(err)
				}
				if got.GetNextPageToken() != "" {
					t.Fatalf("next_page_token = %q, want a complete page", got.GetNextPageToken())
				}
				var names []string
				for _, ip := range got.GetInstanceProfiles() {
					names = append(names, ip.GetName())
					want, err := getProfileRPC(t, replica, ip.GetName())
					if err != nil {
						t.Fatal(err)
					}
					if !proto.Equal(ip, want) {
						t.Fatalf("listed %v, want it as GetInstanceProfile returns it: %v", ip, want)
					}
				}
				wantNames := []string{
					parentName + "/instanceProfiles/Batch", parentName + "/instanceProfiles/stale",
					parentName + "/instanceProfiles/web",
				}
				if !slices.Equal(names, wantNames) {
					t.Fatalf("listed %q, want %q", names, wantNames)
				}
				web := got.GetInstanceProfiles()[2]
				if web.GetEtag() != before.Version || len(web.GetStatus().GetRoles()) != 1 ||
					len(got.GetInstanceProfiles()[1].GetSpec().GetRoles()) != 0 {
					t.Fatalf("web = %v, stale = %v; want web at %q with S3Access and stale without a role",
						web, got.GetInstanceProfiles()[1], before.Version)
				}

				var paged []string
				token := ""
				for pages := 1; ; pages++ {
					pg, err := listProfilesRPC(t, replica, &iamv1.ListInstanceProfilesRequest{
						Parent: parentName, PageSize: 1, PageToken: token,
					})
					if err != nil {
						t.Fatal(err)
					}
					if len(pg.GetInstanceProfiles()) != 1 {
						t.Fatalf("page %d holds %d profiles, want 1", pages, len(pg.GetInstanceProfiles()))
					}
					paged = append(paged, pg.GetInstanceProfiles()[0].GetName())
					if token = pg.GetNextPageToken(); token == "" {
						break
					}
					if pages > 4 {
						t.Fatalf("still truncated after %d pages: %q", pages, paged)
					}
				}
				if want := append([]string{parentName + "/instanceProfiles/api"}, wantNames...); !slices.Equal(paged, want) {
					t.Fatalf("paged %q, want %q", paged, want)
				}
			}
			if again := storedProfile(t, b, "web"); again.Version != before.Version {
				t.Fatalf("listing wrote the profile: version %q, want %q", again.Version, before.Version)
			}
		})
	}
}

// TestListInstanceProfilesRPCErrors: a parent that is not
// projects/{project}, a bad path_prefix, a page_size outside 1 to 1000 or
// a page_token character outside [ -ÿ] is INVALID_ARGUMENT
// (ValidationError); a page_token this server did not return is
// INVALID_ARGUMENT (InvalidInput); no matching profile is an empty,
// complete page; a store failure on the profiles or their roles is
// INTERNAL without backend detail, never a page.
func TestListInstanceProfilesRPCErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedProfileAt(t, b, "web", "/")

	for _, p := range []string{"", proj, "projects/", "projects/Bad_Project", parentName + "/instanceProfiles"} {
		_, err := listProfilesRPC(t, e, &iamv1.ListInstanceProfilesRequest{Parent: p})
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	}
	for _, req := range []*iamv1.ListInstanceProfilesRequest{
		{PathPrefix: "app/"},
		{PathPrefix: "/é/"},
		{PathPrefix: "/" + strings.Repeat("p", iam.MaxPathPrefixLen)},
		{PageSize: -1},
		{PageSize: 1001},
		{PageToken: "Ā"},
		{PageToken: "a\tb"},
	} {
		req.Parent = parentName
		_, err := listProfilesRPC(t, e, req)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	}
	for _, tok := range []string{"!!!", "V2Vi"} {
		_, err := listProfilesRPC(t, e, &iamv1.ListInstanceProfilesRequest{Parent: parentName, PageToken: tok})
		wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
	}
	got, err := listProfilesRPC(t, e, &iamv1.ListInstanceProfilesRequest{Parent: parentName, PathPrefix: "/none/"})
	if err != nil || len(got.GetInstanceProfiles()) != 0 || got.GetNextPageToken() != "" {
		t.Fatalf("no matching profile: %v, %v; want an empty, complete page", got, err)
	}

	for _, k := range []iam.Kind{iam.KindInstanceProfile, iam.KindRole} {
		fb := failingList{memstore.New(), k, errors.New("backend down")}
		fe := newEnvOn(t, fb, &now)
		seedInstanceProfile(t, fb, "web", "r")
		got, err := listProfilesRPC(t, fe, &iamv1.ListInstanceProfilesRequest{Parent: parentName})
		if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "backend down") || got != nil {
			t.Fatalf("store failure on %s: %v, %v; want a bare INTERNAL and no page", k, got, err)
		}
	}
}

func profilesForRoleRPC(
	t *testing.T, e *env, req *iamv1.ListInstanceProfilesForRoleRequest,
) (*iamv1.ListInstanceProfilesForRoleResponse, error) {
	t.Helper()
	return e.profiles.ListInstanceProfilesForRole(t.Context(), req)
}

// TestListInstanceProfilesForRoleRPC:
// InstanceProfileService.ListInstanceProfilesForRole lists the profiles
// that hold role_name, in any case, ordered by case-folded name, each
// exactly as GetInstanceProfile returns it (envelope, etag, path, ARN and
// the role as GetRole returns it); page_size bounds a page and
// next_page_token, set only on a truncated page, continues it until every
// profile is listed once. A second server on the same store (another
// replica, or this one restarted) gives the same answer, and listing
// writes nothing. On both store backends.
func TestListInstanceProfilesForRoleRPC(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			seedRole(t, e, "Other")
			seedProfileAt(t, b, "web", "/app/", "S3Access")
			seedProfileAt(t, b, "Batch", "/app/batch/", "s3access")
			seedProfileAt(t, b, "api", "/", "S3ACCESS")
			seedProfileAt(t, b, "db", "/", "Other")
			seedProfileAt(t, b, "empty", "/")
			before := storedProfile(t, b, "web")
			wantNames := []string{
				parentName + "/instanceProfiles/api", parentName + "/instanceProfiles/Batch",
				parentName + "/instanceProfiles/web",
			}

			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				role, err := replica.roles.GetRole(t.Context(), &iamv1.GetRoleRequest{Name: parentName + "/roles/S3Access"})
				if err != nil {
					t.Fatal(err)
				}
				got, err := profilesForRoleRPC(t, replica, &iamv1.ListInstanceProfilesForRoleRequest{
					Parent: parentName, RoleName: "s3ACCESS",
				})
				if err != nil {
					t.Fatal(err)
				}
				if got.GetNextPageToken() != "" {
					t.Fatalf("next_page_token = %q, want a complete page", got.GetNextPageToken())
				}
				var names []string
				for _, ip := range got.GetInstanceProfiles() {
					names = append(names, ip.GetName())
					want, err := getProfileRPC(t, replica, ip.GetName())
					if err != nil {
						t.Fatal(err)
					}
					if !proto.Equal(ip, want) {
						t.Fatalf("listed %v, want it as GetInstanceProfile returns it: %v", ip, want)
					}
					if rs := ip.GetStatus().GetRoles(); len(rs) != 1 || !proto.Equal(rs[0], role) {
						t.Fatalf("%s roles = %v, want S3Access as GetRole returns it: %v", ip.GetName(), rs, role)
					}
				}
				if !slices.Equal(names, wantNames) {
					t.Fatalf("listed %q, want %q", names, wantNames)
				}
				if web := got.GetInstanceProfiles()[2]; web.GetEtag() != before.Version {
					t.Fatalf("web etag = %q, want the version read %q", web.GetEtag(), before.Version)
				}

				var paged []string
				token := ""
				for pages := 1; ; pages++ {
					pg, err := profilesForRoleRPC(t, replica, &iamv1.ListInstanceProfilesForRoleRequest{
						Parent: parentName, RoleName: "S3Access", PageSize: 1, PageToken: token,
					})
					if err != nil {
						t.Fatal(err)
					}
					if len(pg.GetInstanceProfiles()) != 1 {
						t.Fatalf("page %d holds %d profiles, want 1", pages, len(pg.GetInstanceProfiles()))
					}
					paged = append(paged, pg.GetInstanceProfiles()[0].GetName())
					if token = pg.GetNextPageToken(); token == "" {
						break
					}
					if pages > 3 {
						t.Fatalf("still truncated after %d pages: %q", pages, paged)
					}
				}
				if !slices.Equal(paged, wantNames) {
					t.Fatalf("paged %q, want %q", paged, wantNames)
				}
			}
			if again := storedProfile(t, b, "web"); again.Version != before.Version {
				t.Fatalf("listing wrote the profile: version %q, want %q", again.Version, before.Version)
			}
		})
	}
}

// TestListInstanceProfilesForRoleRPCErrors: a parent that is not
// projects/{project}, a bad role_name, a page_size outside 1 to 1000 or a
// page_token character outside [ -ÿ] is INVALID_ARGUMENT
// (ValidationError); a page_token this server did not return is
// INVALID_ARGUMENT (InvalidInput); an unknown role is NOT_FOUND
// (NoSuchEntity), also when a profile still names it; a role in no
// profile is an empty, complete page; a store failure on the role or the
// profiles is INTERNAL without backend detail, never a page.
func TestListInstanceProfilesForRoleRPCErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedRole(t, e, "Known")
	seedRole(t, e, "Lonely")
	seedProfileAt(t, b, "web", "/", "Known")
	seedProfileAt(t, b, "stale", "/", "Gone")

	for _, p := range []string{"", proj, "projects/", "projects/Bad_Project", parentName + "/roles"} {
		_, err := profilesForRoleRPC(t, e, &iamv1.ListInstanceProfilesForRoleRequest{Parent: p, RoleName: "Known"})
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	}
	for _, req := range []*iamv1.ListInstanceProfilesForRoleRequest{
		{RoleName: ""},
		{RoleName: strings.Repeat("r", 65)},
		{RoleName: "a/b"},
		{RoleName: "rôle"},
		{RoleName: "Known", PageSize: -1},
		{RoleName: "Known", PageSize: 1001},
		{RoleName: "Known", PageToken: "Ā"},
		{RoleName: "Known", PageToken: "a\tb"},
	} {
		req.Parent = parentName
		_, err := profilesForRoleRPC(t, e, req)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	}
	for _, tok := range []string{"!!!", "V2Vi"} {
		_, err := profilesForRoleRPC(t, e, &iamv1.ListInstanceProfilesForRoleRequest{
			Parent: parentName, RoleName: "Known", PageToken: tok,
		})
		wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
	}
	for _, r := range []string{"missing", "Gone"} {
		_, err := profilesForRoleRPC(t, e, &iamv1.ListInstanceProfilesForRoleRequest{Parent: parentName, RoleName: r})
		wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	}
	got, err := profilesForRoleRPC(t, e, &iamv1.ListInstanceProfilesForRoleRequest{Parent: parentName, RoleName: "Lonely"})
	if err != nil || len(got.GetInstanceProfiles()) != 0 || got.GetNextPageToken() != "" {
		t.Fatalf("role in no profile: %v, %v; want an empty, complete page", got, err)
	}

	down := errors.New("backend down")
	for name, fb := range map[string]store.Backend{
		"role get":     failingGet{memstore.New(), iam.KindRole, down},
		"profile list": failingList{memstore.New(), iam.KindInstanceProfile, down},
	} {
		fe := newEnvOn(t, fb, &now)
		seedRole(t, fe, "r")
		seedInstanceProfile(t, fb, "web", "r")
		got, err := profilesForRoleRPC(t, fe, &iamv1.ListInstanceProfilesForRoleRequest{Parent: parentName, RoleName: "r"})
		if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "backend down") || got != nil {
			t.Fatalf("store failure on %s: %v, %v; want a bare INTERNAL and no page", name, got, err)
		}
	}
}

func removeRoleRPC(t *testing.T, e *env, name, role string) (*iamv1.RemoveRoleFromInstanceProfileResponse, error) {
	t.Helper()
	return e.profiles.RemoveRoleFromInstanceProfile(t.Context(), &iamv1.RemoveRoleFromInstanceProfileRequest{
		Name: name, RoleName: role,
	})
}

// TestRemoveRoleFromInstanceProfileRPC:
// InstanceProfileService.RemoveRoleFromInstanceProfile removes the role,
// named in any case, from the profile, named in any case, and answers an
// empty response; the role and the profile stay, and GetInstanceProfile on
// a second server over the same store (another replica, or this one
// restarted) shows the profile without the role at the next generation. A
// repeat on that server is NOT_FOUND (NoSuchEntity), as in AWS, and writes
// nothing. On both store backends.
func TestRemoveRoleFromInstanceProfileRPC(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			seedRole(t, e, "S3Access")
			seedProfileAt(t, b, "Webserver", "/app/", "S3Access")
			profile := parentName + "/instanceProfiles/Webserver"

			got, err := removeRoleRPC(t, e, parentName+"/instanceProfiles/webSERVER", "s3access")
			if err != nil {
				t.Fatalf("RemoveRoleFromInstanceProfile: %v", err)
			}
			if !proto.Equal(got, &iamv1.RemoveRoleFromInstanceProfileResponse{}) {
				t.Fatalf("response = %v, want empty", got)
			}

			replica := newEnvOn(t, b, &now)
			ip, err := getProfileRPC(t, replica, profile)
			if err != nil {
				t.Fatal(err)
			}
			if len(ip.GetSpec().GetRoles()) != 0 || len(ip.GetStatus().GetRoles()) != 0 ||
				ip.GetGeneration() != 2 || ip.GetSpec().GetPath() != "/app/" {
				t.Fatalf("after remove: %v, want path /app/, no role, generation 2", ip)
			}
			if _, err := replica.roles.GetRole(t.Context(), &iamv1.GetRoleRequest{
				Name: parentName + "/roles/S3Access",
			}); err != nil {
				t.Fatalf("the role did not stay: %v", err)
			}

			stored := storedProfile(t, b, "Webserver")
			_, err = removeRoleRPC(t, replica, profile, "S3Access")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			if again := storedProfile(t, b, "Webserver"); again.Version != stored.Version {
				t.Fatalf("the repeat wrote the profile: version %q, want %q", again.Version, stored.Version)
			}
		})
	}
}

// TestRemoveRoleFromInstanceProfileRPCErrors: a name that is not
// projects/{project}/instanceProfiles/{id}, a bad project, an
// InstanceProfileName or role_name outside the AWS rule is
// INVALID_ARGUMENT (ValidationError); an unknown profile, an unknown role
// and a role not in the profile are NOT_FOUND (NoSuchEntity); a
// service-linked role is FAILED_PRECONDITION (UnmodifiableEntity); a store
// failure on the write is INTERNAL without backend detail. None of them
// changes the profile.
func TestRemoveRoleFromInstanceProfileRPCErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	seedRole(t, e, "inside")
	seedRole(t, e, "outside")
	seedInstanceProfile(t, b, "web", "inside")
	before := storedProfile(t, b, "web")
	web := parentName + "/instanceProfiles/web"

	for _, n := range []string{
		"", "web", parentName, parentName + "/roles/web", parentName + "/instanceProfiles/",
		parentName + "/instanceProfiles/a/b", "projects/Bad_Project/instanceProfiles/web",
		parentName + "/instanceProfiles/a b", parentName + "/instanceProfiles/é",
		parentName + "/instanceProfiles/" + strings.Repeat("p", iam.MaxInstanceProfileNameLen+1),
	} {
		_, err := removeRoleRPC(t, e, n, "inside")
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	}
	for _, r := range []string{"", strings.Repeat("r", 65), "a/b", "a b", "rôle"} {
		_, err := removeRoleRPC(t, e, web, r)
		wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	}
	for _, c := range []struct{ profile, role string }{
		{parentName + "/instanceProfiles/missing", "inside"},
		{parentName + "/instanceProfiles/" + strings.Repeat("p", iam.MaxInstanceProfileNameLen), "inside"},
		{web, "missing"},
		{web, "outside"},
	} {
		_, err := removeRoleRPC(t, e, c.profile, c.role)
		wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	}
	slr := seedLinkedRole(t, b, "linked")
	seedInstanceProfile(t, b, "svc", slr.Name)
	_, err := removeRoleRPC(t, e, parentName+"/instanceProfiles/svc", slr.Name)
	wantAWS(t, err, codes.FailedPrecondition, "UnmodifiableEntity")
	if got := storedProfile(t, b, "web"); got.Version != before.Version {
		t.Fatalf("a refused request wrote the profile: version %q, want %q", got.Version, before.Version)
	}

	inner := memstore.New()
	fe := newEnvOn(t, failingUpdate{inner, iam.KindInstanceProfile, errors.New("backend down")}, &now)
	seedRole(t, fe, "r")
	seedInstanceProfile(t, inner, "web", "r")
	got, err := removeRoleRPC(t, fe, web, "r")
	if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "backend down") || got != nil {
		t.Fatalf("store failure on the write: %v, %v; want a bare INTERNAL and no response", got, err)
	}
	if roles := storedProfile(t, inner, "web").Object.Roles; len(roles) != 1 {
		t.Fatalf("after a failed write the profile holds %q, want the role kept", roles)
	}
}
