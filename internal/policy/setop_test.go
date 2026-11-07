package policy_test

import (
	"errors"
	"testing"

	"github.com/popododo0720/vws-iam/internal/policy"
)

// TestConditionSetOperators follows the AWS IAM guide pages on single and
// multivalued context keys and on conditions with multiple values:
// ForAllValues holds when every request value matches a policy value, and
// also when the key is missing or empty; ForAnyValue holds when some
// request value matches, and never for a missing or empty key unless
// IfExists. Under a negated operator a request value passes when it
// matches none of the policy values (a NOR).
func TestConditionSetOperators(t *testing.T) {
	doc := func(cond string) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:DeleteTags",` +
			`"Resource":"arn:vws:ec2:kr-central-1:` + acct + `:instance/*","Condition":` + cond + `}}`
	}
	tagKeys := `{"aws:TagKeys":["environment","cost-center"]}`
	// The two AWS example policies, verbatim but for the partition.
	allValues := doc(`{"ForAllValues:StringEquals":` + tagKeys + `,"Null":{"aws:TagKeys":"false"}}`)
	anyValue := doc(`{"ForAnyValue:StringEquals":` + tagKeys + `}`)
	allNoNull := doc(`{"ForAllValues:StringEquals":` + tagKeys + `}`)
	anyIfExists := doc(`{"ForAnyValue:StringEqualsIfExists":` + tagKeys + `}`)
	allNot := doc(`{"ForAllValues:StringNotEquals":` + tagKeys + `}`)
	anyNot := doc(`{"ForAnyValue:StringNotEquals":` + tagKeys + `}`)
	anyNotIfExists := doc(`{"ForAnyValue:StringNotEqualsIfExists":` + tagKeys + `}`)
	anyLike := doc(`{"ForAnyValue:StringLike":{"aws:TagKeys":"cost-*"}}`)
	allNotLike := doc(`{"ForAllValues:StringNotLike":{"aws:TagKeys":["secret*","admin*"]}}`)
	anyIP := doc(`{"ForAnyValue:IpAddress":{"vws:Addresses":"192.0.2.0/24"}}`)
	allNumeric := doc(`{"ForAllValues:NumericLessThan":{"vws:Sizes":"10"}}`)
	anyVar := doc(`{"ForAnyValue:StringEquals":{"aws:TagKeys":"owner-${aws:username}"}}`)
	twoKeys := doc(`{"ForAnyValue:StringEquals":{"aws:TagKeys":"environment","vws:Teams":["red","blue"]}}`)
	single := doc(`{"StringNotEquals":` + tagKeys + `}`)

	keys := func(v ...string) map[string][]string { return map[string][]string{"aws:TagKeys": v} }
	empty := map[string][]string{"aws:TagKeys": {}}
	alice := func(v ...string) map[string][]string {
		return map[string][]string{"aws:TagKeys": v, "aws:username": {"alice"}}
	}
	teams := func(v ...string) map[string][]string {
		return map[string][]string{"aws:TagKeys": {"environment"}, "vws:Teams": v}
	}
	for _, tc := range []struct {
		name, doc string
		ctx       map[string][]string
		want      bool
	}{
		// AWS example table for ForAllValues with the Null check.
		{"all: environment", allValues, keys("environment"), true},
		{"all: cost-center", allValues, keys("cost-center"), true},
		{"all: both", allValues, keys("environment", "cost-center"), true},
		{"all: environment and dept", allValues, keys("environment", "dept"), false},
		{"all: missing key, Null false", allValues, nil, false},
		// AWS example table for ForAnyValue.
		{"any: environment", anyValue, keys("environment"), true},
		{"any: cost-center", anyValue, keys("cost-center"), true},
		{"any: both", anyValue, keys("environment", "cost-center"), true},
		{"any: environment and dept", anyValue, keys("environment", "dept"), true},
		{"any: dept", anyValue, keys("dept"), false},
		{"any: missing key", anyValue, nil, false},
		// Missing and empty keys.
		{"all without Null: missing key", allNoNull, nil, true},
		{"all without Null: empty key", allNoNull, empty, true},
		{"any: empty key", anyValue, empty, false},
		{"any IfExists: missing key", anyIfExists, nil, true},
		{"any IfExists: empty key", anyIfExists, empty, true},
		{"any IfExists: present still tested", anyIfExists, keys("dept"), false},
		{"any IfExists: present and matching", anyIfExists, keys("dept", "environment"), true},
		// Negated operators.
		{"all not: none listed", allNot, keys("dept", "owner"), true},
		{"all not: one listed", allNot, keys("dept", "environment"), false},
		{"all not: missing key", allNot, nil, true},
		{"any not: one unlisted", anyNot, keys("environment", "dept"), true},
		{"any not: all listed", anyNot, keys("environment", "cost-center"), false},
		{"any not: missing key", anyNot, nil, false},
		{"any not IfExists: missing key", anyNotIfExists, nil, true},
		{"single not: one listed", single, keys("dept", "environment"), false},
		{"single not: none listed", single, keys("dept"), true},
		// Other operator kinds.
		{"any like", anyLike, keys("dept", "cost-center"), true},
		{"any like: no match", anyLike, keys("dept"), false},
		{"all not like: clean", allNotLike, keys("dept", "owner"), true},
		{"all not like: one secret", allNotLike, keys("dept", "secret-key"), false},
		{"any ip", anyIP, map[string][]string{"vws:Addresses": {"198.51.100.1", "192.0.2.9"}}, true},
		{"any ip: none inside", anyIP, map[string][]string{"vws:Addresses": {"198.51.100.1"}}, false},
		{"all numeric", allNumeric, map[string][]string{"vws:Sizes": {"1", "9"}}, true},
		{"all numeric: one too big", allNumeric, map[string][]string{"vws:Sizes": {"1", "10"}}, false},
		{"all numeric: not a number", allNumeric, map[string][]string{"vws:Sizes": {"1", "x"}}, false},
		// A policy variable in a value, and the AND of two keys.
		{"any variable", anyVar, alice("dept", "owner-alice"), true},
		{"any variable: other user", anyVar, alice("owner-bob"), false},
		{"two keys: both", twoKeys, teams("green", "blue"), true},
		{"two keys: one", twoKeys, teams("green"), false},
	} {
		r := req("ec2:DeleteTags", "arn:vws:ec2:kr-central-1:"+acct+":instance/i-1", tc.ctx)
		if got := policy.Evaluate(r, []policy.Named{must(t, tc.doc)}, nil).Allowed; got != tc.want {
			t.Errorf("%s: allowed %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestConditionSetOperatorsParse checks that a set operator is kept apart
// from its base operator and IfExists, and that an unknown qualifier or a
// set operator on Null is MalformedPolicyDocument.
func TestConditionSetOperatorsParse(t *testing.T) {
	stmt := func(op string) string {
		return `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*",` +
			`"Condition":{"` + op + `":{"Aws:TagKeys":"false"}}}}`
	}
	for op, want := range map[string]policy.Condition{
		"ForAnyValue:StringEquals":            {Op: "StringEquals", Set: policy.ForAnyValue},
		"ForAllValues:StringLikeIfExists":     {Op: "StringLike", Set: policy.ForAllValues, IfExists: true},
		"ForAnyValue:StringNotEqualsIfExists": {Op: "StringNotEquals", Set: policy.ForAnyValue, IfExists: true},
		"ForAllValues:ArnNotLike":             {Op: "ArnNotLike", Set: policy.ForAllValues},
		"StringEquals":                        {Op: "StringEquals"},
	} {
		d, err := policy.Parse(stmt(op))
		if err != nil {
			t.Errorf("%s: %v", op, err)
			continue
		}
		c := d.Statements[0].Conditions[0]
		if c.Op != want.Op || c.Set != want.Set || c.IfExists != want.IfExists || c.Key != "aws:tagkeys" {
			t.Errorf("%s: parsed %+v, want %+v", op, c, want)
		}
	}
	for _, op := range []string{
		"ForAnyValue:Null", "ForAllValues:NullIfExists", "ForAnyValues:StringEquals",
		"forAnyValue:StringEquals", "ForAnyValue:", "ForAnyValue:ForAllValues:StringEquals",
		"ForAnyValueStringEquals", "StringEquals:ForAnyValue", "ForAnyValue:StringMagic",
	} {
		if _, err := policy.Parse(stmt(op)); !errors.Is(err, policy.ErrMalformed) {
			t.Errorf("%s: %v, want MalformedPolicyDocument", op, err)
		}
	}
}
