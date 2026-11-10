package grpcapi_test

import (
	"testing"

	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// TestValidationWireMessages pins the client-visible text of the iam and
// policy validation errors a request can reach, so naming kinds and fields
// in the domain errors never changes a wire message (#303).
func TestValidationWireMessages(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	e.createUser(t, ctx, "alice")
	badEffect := `{"Version":"2012-10-17","Statement":{"Effect":"Maybe","Action":"s3:*","Resource":"*"}}`
	cases := []struct {
		name string
		call func() error
		want string
	}{
		{"role max session duration", func() error {
			_, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{Parent: parentName, RoleId: "r", Role: &iamv1.Role{
				Spec: &iamv1.RoleSpec{AssumeRolePolicy: slrTrust, MaxSessionDurationSeconds: 10},
			}})
			return err
		}, `invalid: max session duration 10s`},
		{"group member twice", func() error {
			_, err := e.groups.CreateGroup(ctx, &iamv1.CreateGroupRequest{Parent: parentName, GroupId: "g", Group: &iamv1.Group{
				Spec: &iamv1.GroupSpec{Members: []string{userName("alice"), userName("alice")}},
			}})
			return err
		}, `store update if IamGroup: invalid: member "alice"`},
		{"policy effect", func() error {
			spec := &iamv1.PolicySpec{Document: badEffect}
			_, err := e.policies.CreatePolicy(ctx, &iamv1.CreatePolicyRequest{
				Parent: parentName, PolicyId: "p", Policy: &iamv1.Policy{Spec: spec},
			})
			return err
		}, `statement 0: MalformedPolicyDocument: Effect "Maybe"`},
	}
	for _, c := range cases {
		if got := status.Convert(c.call()).Message(); got != c.want {
			t.Errorf("%s: wire message %q, want %q", c.name, got, c.want)
		}
	}
}
