package grpcapi_test

import (
	"errors"
	"maps"
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

func listRoleTagsRPC(t *testing.T, e *env, req *iamv1.ListRoleTagsRequest) (*iamv1.ListRoleTagsResponse, error) {
	t.Helper()
	return e.roles.ListRoleTags(t.Context(), req)
}

// TestListRoleTagsRPC: RoleService.ListRoleTags returns the stored tags
// sorted by key for any case of the role name; page_size bounds a page and
// next_page_token, set only on a truncated page, continues it until every
// tag is listed once. The same request again, and on a second server on
// the same store (another replica, or this one restarted), gives the same
// answer, and listing writes nothing. On both store backends.
func TestListRoleTagsRPC(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			tags := map[string]string{"Team": "core", "env": "prod", "Cost": "", "b": "2", "a": "1"}
			version := seedTaggedRole(t, b, proj, "App", tags)
			wantKeys := []string{"Cost", "Team", "a", "b", "env"}

			for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
				for _, n := range []string{"App", "app", "APP"} {
					got, err := listRoleTagsRPC(t, replica, &iamv1.ListRoleTagsRequest{Name: parentName + "/roles/" + n})
					if err != nil {
						t.Fatalf("ListRoleTags(%q): %v", n, err)
					}
					var keys []string
					for _, tg := range got.GetTags() {
						keys = append(keys, tg.GetKey())
						if tg.GetValue() != tags[tg.GetKey()] {
							t.Fatalf("tag %q = %q, want %q", tg.GetKey(), tg.GetValue(), tags[tg.GetKey()])
						}
					}
					if !slices.Equal(keys, wantKeys) || got.GetNextPageToken() != "" {
						t.Fatalf("ListRoleTags(%q) = %v, next %q; want keys %v and a complete page",
							n, keys, got.GetNextPageToken(), wantKeys)
					}
				}

				paged, token, pages := map[string]string{}, "", 0
				for {
					req := &iamv1.ListRoleTagsRequest{Name: parentName + "/roles/App", PageSize: 2, PageToken: token}
					got, err := listRoleTagsRPC(t, replica, req)
					if err != nil {
						t.Fatal(err)
					}
					again, err := listRoleTagsRPC(t, replica, req)
					if err != nil || !proto.Equal(got, again) {
						t.Fatalf("repeated page: %v, %v; want %v", again, err, got)
					}
					pages++
					if len(got.GetTags()) > 2 {
						t.Fatalf("page of %d tags, want at most 2", len(got.GetTags()))
					}
					for _, tg := range got.GetTags() {
						if _, dup := paged[tg.GetKey()]; dup {
							t.Fatalf("tag %q listed twice", tg.GetKey())
						}
						paged[tg.GetKey()] = tg.GetValue()
					}
					if token = got.GetNextPageToken(); token == "" {
						break
					}
				}
				if !maps.Equal(paged, tags) || pages != 3 {
					t.Fatalf("paged %v in %d pages, want %v in 3", paged, pages, tags)
				}
			}

			plain := seedTaggedRole(t, b, proj, "Plain", nil)
			got, err := listRoleTagsRPC(t, e, &iamv1.ListRoleTagsRequest{Name: parentName + "/roles/Plain"})
			if err != nil || len(got.GetTags()) != 0 || got.GetNextPageToken() != "" {
				t.Fatalf("untagged role: %v, %v; want an empty, complete page", got, err)
			}
			for name, want := range map[string]string{"App": version, "Plain": plain} {
				r, err := store.Get[iam.Role](t.Context(), store.Scoped(b, proj), name)
				if err != nil {
					t.Fatal(err)
				}
				if r.Version != want {
					t.Fatalf("ListRoleTags wrote role %s: version %q, want %q", name, r.Version, want)
				}
			}
		})
	}
}

// TestListRoleTagsRPCErrors: a name that is not
// projects/{project}/roles/{id}, a bad project, a RoleName outside the AWS
// rule, a page_size outside 1 to 1000 and a page_token character outside
// [\u0020-\u00FF] are INVALID_ARGUMENT (ValidationError) and a page_token
// not issued here is InvalidInput, all before any store access; an unknown
// role is NOT_FOUND (NoSuchEntity) with the AWS message, and a store
// failure is a bare INTERNAL (console-api answers ServiceFailure), as for
// every RPC here, without backend detail.
func TestListRoleTagsRPCErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	seedTaggedRole(t, b, proj, "App", map[string]string{"k": "v"})
	broken := newEnvOn(t, failingGet{b, iam.KindRole, errors.New("backend exploded")}, &now)
	app := parentName + "/roles/App"
	for _, tc := range []struct {
		name string
		req  *iamv1.ListRoleTagsRequest
		aws  string
	}{
		{"empty name", &iamv1.ListRoleTagsRequest{}, "ValidationError"},
		{"wrong collection", &iamv1.ListRoleTagsRequest{Name: parentName + "/users/App"}, "ValidationError"},
		{"nested role", &iamv1.ListRoleTagsRequest{Name: app + "/x"}, "ValidationError"},
		{"bad project", &iamv1.ListRoleTagsRequest{Name: "projects/Bad_Project/roles/App"}, "ValidationError"},
		{"role bad character", &iamv1.ListRoleTagsRequest{Name: parentName + "/roles/a b"}, "ValidationError"},
		{"role too long", &iamv1.ListRoleTagsRequest{Name: app + strings.Repeat("r", 62)}, "ValidationError"},
		{"page_size negative", &iamv1.ListRoleTagsRequest{Name: app, PageSize: -1}, "ValidationError"},
		{"page_size too large", &iamv1.ListRoleTagsRequest{Name: app, PageSize: 1001}, "ValidationError"},
		{"page_token control character", &iamv1.ListRoleTagsRequest{Name: app, PageToken: "a\x01"}, "ValidationError"},
		{"page_token not issued", &iamv1.ListRoleTagsRequest{Name: app, PageToken: "!!!"}, "InvalidInput"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listRoleTagsRPC(t, broken, tc.req)
			wantAWS(t, err, codes.InvalidArgument, tc.aws)
			if got != nil {
				t.Fatalf("response %v with an error", got)
			}
		})
	}

	e := newEnvOn(t, b, &now)
	if _, err := listRoleTagsRPC(t, e, &iamv1.ListRoleTagsRequest{Name: app, PageSize: 1000}); err != nil {
		t.Fatalf("page_size 1000 rejected: %v", err)
	}
	_, err := listRoleTagsRPC(t, e, &iamv1.ListRoleTagsRequest{Name: parentName + "/roles/Missing"})
	wantAWS(t, err, codes.NotFound, "NoSuchEntity")
	if want := "The role with name Missing cannot be found."; status.Convert(err).Message() != want {
		t.Fatalf("message %q, want %q", status.Convert(err).Message(), want)
	}

	got, err := listRoleTagsRPC(t, broken, &iamv1.ListRoleTagsRequest{Name: app})
	if status.Code(err) != codes.Internal || got != nil || strings.Contains(err.Error(), "backend exploded") {
		t.Fatalf("store failure: %v, %v; want no response and no backend detail", got, err)
	}
}
