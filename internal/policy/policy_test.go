package policy_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/policy"
)

const acct = "111122223333"

func must(t *testing.T, doc string) policy.Named {
	t.Helper()
	d, err := policy.ParseIdentity(doc)
	if err != nil {
		t.Fatalf("parse %s: %v", doc, err)
	}
	return policy.Named{Name: "p", Doc: d}
}

func req(action, resource string, ctx map[string][]string) policy.Request {
	return policy.Request{Principal: "arn:vws:iam::" + acct + ":user/alice", Account: acct, Action: action, Resource: resource, Context: ctx}
}

// Cases adapted from the AWS IAM user guide policy examples and the
// policy evaluation logic page.
func TestEvaluateAWSExamples(t *testing.T) {
	s3list := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":"arn:vws:s3:::example-bucket"},{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:vws:s3:::example-bucket/*"}]}`
	denyAllButIAM := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","NotAction":"iam:*","Resource":"*"}}`
	adminAll := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	mfa := `{"Version":"2012-10-17","Statement":[{"Sid":"AllowAll","Effect":"Allow","Action":"ec2:*","Resource":"*"},{"Sid":"DenyStopWithoutMFA","Effect":"Deny","Action":["ec2:StopInstances","ec2:TerminateInstances"],"Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}]}`
	ip := `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":["192.0.2.0/24","203.0.113.0/24"]}}}}`
	region := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*","Condition":{"StringEquals":{"aws:RequestedRegion":["kr-central-1"]}}}}`
	homeDir := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:vws:s3:::home/${aws:username}/*"}}`
	expiring := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"2026-12-31T23:59:59Z"}}}}`
	notRes := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","NotResource":["arn:vws:s3:::secret","arn:vws:s3:::secret/*"]}}`
	arnLike := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:PassRole","Resource":"*","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:vws:iam::*:user/a*"}}}}`
	like := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:vws:s3:::b","Condition":{"StringLike":{"s3:prefix":["home/${aws:username}/*"]}}}}`
	user := map[string][]string{"aws:username": {"alice"}}

	cases := []struct {
		name     string
		policies []string
		r        policy.Request
		allowed  bool
		reason   string
	}{
		{"implicit deny with no policy", nil, req("s3:GetObject", "arn:vws:s3:::x/y", nil), false, "no identity-based policy"},
		{"s3 object allowed", []string{s3list}, req("s3:GetObject", "arn:vws:s3:::example-bucket/a/b", nil), true, ""},
		{"s3 list on object denied", []string{s3list}, req("s3:ListBucket", "arn:vws:s3:::example-bucket/a", nil), false, ""},
		{"action is case-insensitive", []string{s3list}, req("S3:getobject", "arn:vws:s3:::example-bucket/a", nil), true, ""},
		{"resource is case-sensitive", []string{s3list}, req("s3:GetObject", "arn:vws:s3:::Example-Bucket/a", nil), false, ""},
		{"explicit deny beats allow", []string{adminAll, denyAllButIAM}, req("ec2:RunInstances", "*", nil), false, "explicit deny"},
		{"NotAction deny leaves iam", []string{adminAll, denyAllButIAM}, req("iam:CreateUser", "*", nil), true, ""},
		{"mfa absent denies stop", []string{mfa}, req("ec2:StopInstances", "arn:vws:ec2:kr-central-1:"+acct+":instance/i-1", nil), false, "DenyStopWithoutMFA"},
		{"mfa false denies stop", []string{mfa}, req("ec2:StopInstances", "*", map[string][]string{"aws:MultiFactorAuthPresent": {"false"}}), false, ""},
		{"mfa true allows stop", []string{mfa}, req("ec2:StopInstances", "*", map[string][]string{"aws:MultiFactorAuthPresent": {"true"}}), true, "AllowAll"},
		{"mfa irrelevant to describe", []string{mfa}, req("ec2:DescribeInstances", "*", nil), true, ""},
		{"source ip inside", []string{adminAll, ip}, req("s3:GetObject", "*", map[string][]string{"aws:SourceIp": {"192.0.2.7"}}), true, ""},
		{"source ip outside", []string{adminAll, ip}, req("s3:GetObject", "*", map[string][]string{"aws:SourceIp": {"198.51.100.1"}}), false, ""},
		{"source ip missing denies (negated op)", []string{adminAll, ip}, req("s3:GetObject", "*", nil), false, ""},
		{"region match", []string{region}, req("ec2:RunInstances", "*", map[string][]string{"aws:RequestedRegion": {"kr-central-1"}}), true, ""},
		{"region mismatch", []string{region}, req("ec2:RunInstances", "*", map[string][]string{"aws:RequestedRegion": {"us-east-1"}}), false, ""},
		{"region missing", []string{region}, req("ec2:RunInstances", "*", nil), false, ""},
		{"policy variable own home", []string{homeDir}, req("s3:GetObject", "arn:vws:s3:::home/alice/f", user), true, ""},
		{"policy variable other home", []string{homeDir}, req("s3:GetObject", "arn:vws:s3:::home/bob/f", user), false, ""},
		{"policy variable unresolved", []string{homeDir}, req("s3:GetObject", "arn:vws:s3:::home/alice/f", nil), false, ""},
		{"date before", []string{expiring}, req("ec2:DescribeVpcs", "*", map[string][]string{"aws:CurrentTime": {"2026-10-14T00:00:00Z"}}), true, ""},
		{"date after", []string{expiring}, req("ec2:DescribeVpcs", "*", map[string][]string{"aws:CurrentTime": {"2027-01-01T00:00:00Z"}}), false, ""},
		{"NotResource excludes", []string{notRes}, req("s3:GetObject", "arn:vws:s3:::secret/x", nil), false, ""},
		{"NotResource includes others", []string{notRes}, req("s3:GetObject", "arn:vws:s3:::public/x", nil), true, ""},
		{"ArnLike segment wildcard", []string{arnLike}, req("iam:PassRole", "*", map[string][]string{"aws:PrincipalArn": {"arn:vws:iam::" + acct + ":user/alice"}}), true, ""},
		{"ArnLike no match", []string{arnLike}, req("iam:PassRole", "*", map[string][]string{"aws:PrincipalArn": {"arn:vws:iam::" + acct + ":role/alice"}}), false, ""},
		{"StringLike with variable", []string{like}, req("s3:ListBucket", "arn:vws:s3:::b", map[string][]string{"aws:username": {"alice"}, "s3:prefix": {"home/alice/docs"}}), true, ""},
		{"StringLike other prefix", []string{like}, req("s3:ListBucket", "arn:vws:s3:::b", map[string][]string{"aws:username": {"alice"}, "s3:prefix": {"home/bob/"}}), false, ""},
		{"mfa age under limit", []string{`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*","Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}}}}`}, req("iam:CreateUser", "*", map[string][]string{"aws:MultiFactorAuthAge": {"120"}}), true, ""},
		{"mfa age over limit", []string{`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*","Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"3600"}}}}`}, req("iam:CreateUser", "*", map[string][]string{"aws:MultiFactorAuthAge": {"7200"}}), false, ""},
		{"condition key case-insensitive", []string{region}, req("ec2:RunInstances", "*", map[string][]string{"AWS:REQUESTEDREGION": {"kr-central-1"}}), true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var ps []policy.Named
			for _, d := range c.policies {
				ps = append(ps, must(t, d))
			}
			got := policy.Evaluate(c.r, ps, nil)
			if got.Allowed != c.allowed || !strings.Contains(got.Reason, c.reason) {
				t.Fatalf("got %+v, want allowed=%v reason~%q", got, c.allowed, c.reason)
			}
		})
	}
}

func TestSessionPolicyOnlyNarrows(t *testing.T) {
	admin := must(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	s3only := must(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)
	ec2only := must(t, `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"ec2:*","Resource":"*"}}`)
	if d := policy.Evaluate(req("s3:GetObject", "*", nil), []policy.Named{admin}, []policy.Named{s3only}); !d.Allowed {
		t.Fatal(d)
	}
	if d := policy.Evaluate(req("ec2:RunInstances", "*", nil), []policy.Named{admin}, []policy.Named{s3only}); d.Allowed || !strings.Contains(d.Reason, "session") {
		t.Fatal(d)
	}
	// A session policy cannot grant what the identity lacks.
	if d := policy.Evaluate(req("ec2:RunInstances", "*", nil), []policy.Named{s3only}, []policy.Named{ec2only}); d.Allowed {
		t.Fatal(d)
	}
}

func TestTrustPolicy(t *testing.T) {
	trust, err := policy.ParseTrust(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:vws:iam::` + acct + `:root"},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}},{"Effect":"Allow","Principal":{"Service":"ec2.vws.internal"},"Action":"sts:AssumeRole"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	set := []policy.Named{{Name: "trust", Doc: trust}}
	r := policy.Request{Principal: "arn:vws:iam::" + acct + ":user/alice", Account: acct, Action: "sts:AssumeRole", Context: map[string][]string{"aws:MultiFactorAuthPresent": {"true"}}}
	if d := policy.Evaluate(r, set, nil); !d.Allowed {
		t.Fatal(d)
	}
	r.Context = nil
	if d := policy.Evaluate(r, set, nil); d.Allowed {
		t.Fatal("trust without MFA allowed")
	}
	other := policy.Request{Principal: "arn:vws:iam::999988887777:user/eve", Account: "999988887777", Action: "sts:AssumeRole", Context: map[string][]string{"aws:MultiFactorAuthPresent": {"true"}}}
	if d := policy.Evaluate(other, set, nil); d.Allowed {
		t.Fatal("foreign account trusted")
	}
	if d := policy.Evaluate(policy.Request{Service: "ec2.vws.internal", Action: "sts:AssumeRole"}, set, nil); !d.Allowed {
		t.Fatal(d)
	}
}

func TestMalformedPolicies(t *testing.T) {
	bad := []string{
		``, `null`, `[]`, `{}`,
		`{"Version":"2012-10-18","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Version":"","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`,
		`{"Version":"2012-10-17"}`,
		`{"Version":"2012-10-17","Statement":[]}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"allow","Action":"*","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","NotAction":"s3:*","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3GetObject","Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"bucket"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"StringMagic":{"a":"b"}}}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"not-an-ip"}}}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"yes"}}}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"tomorrow"}}}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Extra":1}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"NumericLessThan":{"aws:MultiFactorAuthAge":"soon"}}}}`,
		`{"Version":"2012-10-17","Statement":[{"Sid":"a","Effect":"Allow","Action":"*","Resource":"*"},{"Sid":"a","Effect":"Deny","Action":"*","Resource":"*"}]}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}} trailing`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":[],"Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":{"x":1},"Resource":"*"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"nobody","Action":"sts:AssumeRole"}}`,
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"Martian":"x"},"Action":"sts:AssumeRole"}}`,
		strings.Repeat(" ", policy.MaxSize+1),
	}
	for _, d := range bad {
		if _, err := policy.Parse(d); !errors.Is(err, policy.ErrMalformed) {
			t.Errorf("%.80q: %v, want MalformedPolicyDocument", d, err)
		}
	}
	if _, err := policy.ParseIdentity(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`); !errors.Is(err, policy.ErrMalformed) {
		t.Errorf("identity policy with principal: %v", err)
	}
	if _, err := policy.ParseTrust(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`); !errors.Is(err, policy.ErrMalformed) {
		t.Errorf("trust policy without principal: %v", err)
	}
}

// TestPolicyVersion follows the AWS IAM Version element page: 2012-10-17
// substitutes policy variables; 2008-10-17 and a missing Version accept
// the document but keep ${...} as literal text; any other value is
// MalformedPolicyDocument.
func TestPolicyVersion(t *testing.T) {
	const stmt = `"Statement":{"Effect":"Allow","Action":"s3:GetObject",` +
		`"Resource":"arn:vws:s3:::home/${aws:username}/*",` +
		`"Condition":{"StringLike":{"s3:prefix":"home/${aws:username}/*"}}}`
	ctx := map[string][]string{"aws:username": {"alice"}, "s3:prefix": {"home/alice/x"}}
	literalCtx := map[string][]string{"aws:username": {"alice"}, "s3:prefix": {"home/${aws:username}/x"}}
	alice := "arn:vws:s3:::home/alice/x"
	literal := "arn:vws:s3:::home/${aws:username}/x"
	cases := []struct {
		name        string
		doc         string
		wantVersion string
		wantVars    bool
	}{
		{"2012-10-17 substitutes variables", `{"Version":"2012-10-17",` + stmt + `}`, policy.Version, true},
		{"2008-10-17 keeps variables literal", `{"Version":"2008-10-17",` + stmt + `}`, policy.Version2008, false},
		{"missing Version keeps variables literal", `{` + stmt + `}`, policy.Version2008, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := must(t, c.doc)
			if n.Doc.Version != c.wantVersion {
				t.Errorf("Version = %q, want %q", n.Doc.Version, c.wantVersion)
			}
			set := []policy.Named{n}
			if got := policy.Evaluate(req("s3:GetObject", alice, ctx), set, nil).Allowed; got != c.wantVars {
				t.Errorf("substituted request allowed = %v, want %v", got, c.wantVars)
			}
			if got := policy.Evaluate(req("s3:GetObject", literal, literalCtx), set, nil).Allowed; got == c.wantVars {
				t.Errorf("literal request allowed = %v, want %v", got, !c.wantVars)
			}
		})
	}
	for _, v := range []string{`"2012-10-18"`, `"2008-10-17 "`, `""`, `"latest"`, `20121017`, `null`, `["2012-10-17"]`} {
		t.Run("rejects Version "+v, func(t *testing.T) {
			doc := `{"Version":` + v + `,` + stmt + `}`
			if _, err := policy.Parse(doc); !errors.Is(err, policy.ErrMalformed) {
				t.Fatalf("Parse(%s) = %v, want MalformedPolicyDocument", doc, err)
			}
		})
	}
}

func TestMatchIsLinear(t *testing.T) {
	p := strings.Repeat("*a", 50) + "b"
	s := strings.Repeat("a", 5000)
	if policy.Match(p, s, false) {
		t.Fatal("matched")
	}
	for _, c := range []struct {
		p, s string
		ok   bool
	}{{"*", "", true}, {"a?c", "abc", true}, {"a?c", "ac", false}, {"ec2:Describe*", "ec2:DescribeVpcs", true}, {"*:*", "s3:x", true}, {"a*b*c", "aXbYc", true}, {"a*b*c", "aXbY", false}} {
		if policy.Match(c.p, c.s, false) != c.ok {
			t.Errorf("Match(%q,%q) != %v", c.p, c.s, c.ok)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`)
	f.Add(`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","NotAction":["s3:*"],"NotResource":"arn:vws:s3:::x","Condition":{"StringLikeIfExists":{"k":["${aws:username}*"]},"Null":{"x":"true"}}}]}`)
	f.Add(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":["1","arn:vws:iam::1:root"]},"Action":"sts:AssumeRole"}}`)
	f.Fuzz(func(t *testing.T, doc string) {
		d, err := policy.Parse(doc)
		if err != nil {
			if !errors.Is(err, policy.ErrMalformed) {
				t.Fatalf("error %v is not MalformedPolicyDocument", err)
			}
			return
		}
		// A parsed policy evaluates without panicking.
		policy.Evaluate(policy.Request{Action: "s3:GetObject", Resource: "arn:vws:s3:::b/k", Context: map[string][]string{"aws:SourceIp": {"10.0.0.1"}, "aws:CurrentTime": {"2026-01-01T00:00:00Z"}}}, []policy.Named{{Name: "f", Doc: d}}, []policy.Named{{Name: "f", Doc: d}})
	})
}

// TestInline checks the inline-policy parse: white space does not count
// toward Size, ParseInline is not held to MaxSize but to the
// PolicyDocument length of Put*Policy, and it still refuses a Principal.
func TestInline(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	padded := strings.Replace(doc, "{", "{"+strings.Repeat(" \n\t\r", policy.MaxSize), 1)
	if got := policy.Size(padded); got != len(doc) {
		t.Errorf("Size = %d, want %d", got, len(doc))
	}
	if got := policy.Size("é ü"); got != 2 {
		t.Errorf("Size counts characters: %d, want 2", got)
	}
	if _, err := policy.Parse(padded); !errors.Is(err, policy.ErrMalformed) {
		t.Errorf("Parse over MaxSize: %v", err)
	}
	if _, err := policy.ParseInline(padded); err != nil {
		t.Errorf("ParseInline over MaxSize: %v", err)
	}
	long := strings.Replace(doc, "{", "{"+strings.Repeat(" ", policy.MaxInlineLength), 1)
	if _, err := policy.ParseInline(long); !errors.Is(err, policy.ErrMalformed) {
		t.Errorf("ParseInline over MaxInlineLength: %v", err)
	}
	withPrincipal := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}}`
	if _, err := policy.ParseInline(withPrincipal); !errors.Is(err, policy.ErrMalformed) {
		t.Errorf("ParseInline with principal: %v", err)
	}
}
