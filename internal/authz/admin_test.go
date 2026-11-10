package authz_test

import (
	"context"
	"testing"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
)

var adminActions = []string{
	"vws:AdminListRegions", "vws:AdminRegisterRegion", "vws:AdminUpdateRegion", "vws:AdminRemoveRegion",
	"vws:AdminTestConnection", "vws:AdminRegisterAwsAccount", "vws:AdminUpdateAwsAccount",
	"vws:AdminRemoveAwsAccount", "vws:AdminMapProject",
}

// TestAdminActionsDenyByDefault checks that only a stored policy naming
// vws:* or * (or the VWSAdministratorAccess document) lets an IAM user or
// role call the admin API.
func TestAdminActionsDenyByDefault(t *testing.T) {
	b := setup(t)
	doc := func(action string) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"` + action + `","Resource":"*"}}`
	}
	for _, p := range []iam.Policy{
		{Name: "EC2Full", ID: "11", DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1", Document: doc("ec2:*")}}},
		{Name: "S3Full", ID: "12", DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1", Document: doc("s3:*")}}},
		{Name: "IAMFull", ID: "13", DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1", Document: doc("iam:*")}}},
		{Name: "VWSFull", ID: "14", DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1", Document: doc("vws:*")}}},
		{Name: "Everything", ID: "15", DefaultVersion: "v1", Versions: []iam.PolicyVersion{{ID: "v1", Document: doc("*")}}},
		{
			Name: policy.VWSAdministratorAccess, ID: "16", DefaultVersion: "v1",
			Versions: []iam.PolicyVersion{{ID: "v1", Document: policy.VWSAdministratorAccessDocument}},
		},
	} {
		put(t, b, p)
	}
	arn := func(n string) string { return "arn:vws:iam::" + acct + ":policy/" + n }
	put(t, b, iam.User{Name: "bob", ID: "20"})
	put(t, b, iam.User{Name: "ops", ID: "21", AttachedPolicies: []string{arn("EC2Full"), arn("S3Full"), arn("IAMFull")}})
	put(t, b, iam.User{Name: "vwsadmin", ID: "22", AttachedPolicies: []string{arn("VWSFull")}})
	put(t, b, iam.User{Name: "superuser", ID: "23", AttachedPolicies: []string{arn("Everything")}})
	put(t, b, iam.User{Name: "operator", ID: "24", AttachedPolicies: []string{arn(policy.VWSAdministratorAccess)}})
	a := authz.New(b, acct, nil)
	ctx := context.Background()
	for _, c := range []struct {
		p       authz.Principal
		allowed bool
	}{
		{authz.Principal{Kind: authz.User, Name: "bob"}, false},
		{authz.Principal{Kind: authz.User, Name: "alice"}, false},
		{authz.Principal{Kind: authz.Role, Name: "reader", ARN: "arn:vws:sts::" + acct + ":assumed-role/reader/s1"}, false},
		{authz.Principal{Kind: authz.User, Name: "ops"}, false},
		{authz.Principal{Kind: authz.User, Name: "vwsadmin"}, true},
		{authz.Principal{Kind: authz.User, Name: "superuser"}, true},
		{authz.Principal{Kind: authz.User, Name: "operator"}, true},
	} {
		for _, action := range adminActions {
			d, err := a.Authorize(ctx, c.p, action, "*", nil)
			if err != nil || d.Allowed != c.allowed {
				t.Errorf("%s %s: %+v %v, want allowed=%v", c.p.Name, action, d, err, c.allowed)
			}
		}
	}
}
