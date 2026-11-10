package policy_test

import (
	"errors"
	"testing"

	"github.com/popododo0720/vws-iam/internal/policy"
)

var adminActions = []string{
	"vws:AdminListRegions",
	"vws:AdminRegisterRegion",
	"vws:AdminUpdateRegion",
	"vws:AdminRemoveRegion",
	"vws:AdminTestConnection",
	"vws:AdminRegisterAwsAccount",
	"vws:AdminUpdateAwsAccount",
	"vws:AdminRemoveAwsAccount",
	"vws:AdminMapProject",
}

func statementDoc(key, action string) string {
	return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","` + key + `":"` + action + `","Resource":"*"}}`
}

func TestAdminActionValidation(t *testing.T) {
	cases := []struct {
		action string
		ok     bool
	}{
		{"vws:Admin*", true},
		{"vws:AdminList*", true},
		{"vws:Admin?istRegions", true},
		{"VWS:adminlistregions", true},
		{"vws:*", true},
		{"vws:GetConsole", true},
		{"ec2:AdminFoo", true},
		{"vws:AdminFoo", false},
		{"vws:AdminListRegion", false},
		{"vws:Admin", false},
		{"VWS:ADMINDELETEEVERYTHING", false},
	}
	for _, a := range adminActions {
		cases = append(cases, struct {
			action string
			ok     bool
		}{a, true})
	}
	for _, c := range cases {
		for _, key := range []string{"Action", "NotAction"} {
			_, err := policy.ParseIdentity(statementDoc(key, c.action))
			if c.ok && err != nil {
				t.Errorf("%s %s: %v", key, c.action, err)
			}
			if !c.ok && !errors.Is(err, policy.ErrMalformed) {
				t.Errorf("%s %s: err %v, want MalformedPolicyDocument", key, c.action, err)
			}
		}
	}
}

func TestAdminActionsNeedAnExplicitGrant(t *testing.T) {
	broad := []string{
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"},` +
			`{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`,
		statementDoc("Action", "iam:*"),
		statementDoc("Action", "*:List*"),
		statementDoc("Action", "ec2:Admin*"),
	}
	explicit := []string{
		statementDoc("Action", "*"), statementDoc("Action", "vws:*"), statementDoc("Action", "vws:Admin*"),
	}
	for _, a := range adminActions {
		for _, doc := range broad {
			if d := policy.Evaluate(req(a, "*", nil), []policy.Named{must(t, doc)}, nil); d.Allowed {
				t.Errorf("%s allowed by %s", a, doc)
			}
		}
		for _, doc := range explicit {
			if d := policy.Evaluate(req(a, "*", nil), []policy.Named{must(t, doc)}, nil); !d.Allowed {
				t.Errorf("%s denied by %s: %s", a, doc, d.Reason)
			}
		}
	}
}

func TestVWSAdministratorAccess(t *testing.T) {
	if policy.VWSAdministratorAccessARN != "arn:vws:iam::aws:policy/VWSAdministratorAccess" {
		t.Fatalf("ARN %q", policy.VWSAdministratorAccessARN)
	}
	p := must(t, policy.VWSAdministratorAccessDocument)
	for _, a := range adminActions {
		if d := policy.Evaluate(req(a, "*", nil), []policy.Named{p}, nil); !d.Allowed {
			t.Errorf("%s: %s", a, d.Reason)
		}
	}
	for _, a := range []string{"iam:CreateUser", "ec2:RunInstances", "s3:GetObject", "sts:AssumeRole", "vws:GetConsole"} {
		if d := policy.Evaluate(req(a, "*", nil), []policy.Named{p}, nil); d.Allowed {
			t.Errorf("%s allowed", a)
		}
	}
}
