package grpcapi_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// keyed is a user with an attached policy and an access key.
type keyed struct {
	user          *iamv1.User
	id, secretKey string
}

func (e *env) keyedUser(t *testing.T, name, doc string) keyed {
	t.Helper()
	ctx := t.Context()
	u := e.createUser(t, ctx, name)
	pol := e.createPolicy(t, ctx, name+"-policy", doc)
	if _, err := e.users.UpdateUser(ctx, &iamv1.UpdateUserRequest{
		User:       &iamv1.User{Name: u.GetName(), Spec: &iamv1.UserSpec{AttachedPolicies: []string{pol.GetName()}}},
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"spec.attached_policies"}},
	}); err != nil {
		t.Fatal(err)
	}
	k, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	n := k.GetAccessKey().GetName()
	return keyed{user: u, id: n[strings.LastIndex(n, "/")+1:], secretKey: k.GetSecretAccessKey()}
}

const decodeAction = "DecodeAuthorizationMessage"

// TestDecodeAuthorizationMessage: a deny from Authorize carries an
// encoded message that only a caller allowed sts:DecodeAuthorizationMessage
// can read, on any replica and after a restart, on both store backends.
func TestDecodeAuthorizationMessage(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			bob := e.keyedUser(t, "bob", `{"Version":"2012-10-17","Statement":[
				{"Sid":"All","Effect":"Allow","Action":"s3:*","Resource":"*"},
				{"Sid":"NoDelete","Effect":"Deny","Action":"s3:DeleteObject","Resource":"arn:vws:s3:::locked/*"}]}`)
			auditor := e.keyedUser(t, "auditor", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"sts:DecodeAuthorizationMessage","Resource":"*"}]}`)
			a, err := e.auth.Authenticate(ctx, e.sign(bob.id, bob.secretKey, ""))
			if err != nil {
				t.Fatal(err)
			}
			pr := a.GetPrincipal()

			// An allow carries no message; a deny does.
			ok, enc, err := e.api.AuthorizeEncoded(ctx, &iamv1.AuthorizeRequest{Principal: pr, Action: "s3:GetObject"})
			if err != nil || ok.GetDecision() != iamv1.Decision_DECISION_ALLOW || enc != "" {
				t.Fatalf("allow: %v %q %v", ok, enc, err)
			}
			res := []string{"arn:vws:s3:::pub/a", "arn:vws:s3:::locked/b"}
			deny, enc, err := e.api.AuthorizeEncoded(ctx, &iamv1.AuthorizeRequest{
				Principal: pr, Action: "s3:DeleteObject", Resources: res,
				Context: map[string]*iamv1.ContextValues{"s3:prefix": {Values: []string{"locked/"}}},
			})
			if err != nil || deny.GetDecision() != iamv1.Decision_DECISION_DENY_EXPLICIT || enc == "" {
				t.Fatalf("deny: %v %q %v", deny, enc, err)
			}
			// Authorize itself answers exactly as before.
			plain, err := e.auth.Authorize(ctx, &iamv1.AuthorizeRequest{
				Principal: pr, Action: "s3:DeleteObject", Resources: res,
			})
			if err != nil || plain.GetDecision() != iamv1.Decision_DECISION_DENY_EXPLICIT ||
				plain.GetMatchedStatement() != "NoDelete" {
				t.Fatalf("authorize: %v %v", plain, err)
			}

			signed := e.stsSign(auditor.id, auditor.secretKey, "", decodeAction)
			got, err := e.api.DecodeAuthorizationMessage(ctx, signed, "", enc)
			if err != nil {
				t.Fatal(err)
			}
			var m struct {
				Allowed           bool `json:"allowed"`
				ExplicitDeny      bool `json:"explicitDeny"`
				MatchedStatements struct {
					Items []struct {
						StatementID, Effect string
					} `json:"items"`
				} `json:"matchedStatements"`
				Context struct {
					Principal  struct{ ID, Name, ARN string }
					Action     string `json:"action"`
					Resource   string `json:"resource"`
					Conditions struct {
						Items []struct {
							Key string `json:"key"`
						} `json:"items"`
					} `json:"conditions"`
				} `json:"context"`
			}
			if err := json.Unmarshal([]byte(got), &m); err != nil {
				t.Fatal(err)
			}
			c := m.Context
			if m.Allowed || !m.ExplicitDeny || len(m.MatchedStatements.Items) != 1 ||
				m.MatchedStatements.Items[0].StatementID != "NoDelete" || m.MatchedStatements.Items[0].Effect != "DENY" ||
				c.Principal.ARN != "arn:vws:iam::acme:user/bob" || c.Principal.Name != "bob" ||
				c.Principal.ID != bob.user.GetStatus().GetUniqueId() ||
				c.Action != "s3:DeleteObject" || c.Resource != "arn:vws:s3:::locked/b" {
				t.Fatalf("decoded %s", got)
			}
			keys := map[string]bool{}
			for _, it := range c.Conditions.Items {
				keys[it.Key] = true
			}
			if !keys["s3:prefix"] || !keys["aws:MultiFactorAuthPresent"] || !keys["aws:userid"] {
				t.Fatalf("conditions %s", got)
			}

			// The same signed request cannot be used twice.
			_, err = e.api.DecodeAuthorizationMessage(ctx, signed, "", enc)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			// A request signed for another STS action is refused.
			_, err = e.api.DecodeAuthorizationMessage(ctx, e.stsSign(auditor.id, auditor.secretKey, "", "AssumeRole"), "", enc)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")

			// Another replica, and a restarted one, decode it the same.
			replica := newEnvOn(t, b, &now)
			fresh := e.stsSign(auditor.id, auditor.secretKey, "", decodeAction)
			again, err := replica.api.DecodeAuthorizationMessage(ctx, fresh, "", enc)
			if err != nil || again != got {
				t.Fatalf("replica: %v\n%s\nwant\n%s", err, again, got)
			}

			// bob may not decode, valid message or not.
			for _, msg := range []string{enc, "x"} {
				_, err = e.api.DecodeAuthorizationMessage(ctx, e.stsSign(bob.id, bob.secretKey, "", decodeAction), "", msg)
				wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			}
			// Tampered input and bounds.
			last := enc[len(enc)-1]
			flipped := enc[:len(enc)-1] + string("AB"[map[bool]int{true: 1}[last == 'A']])
			for _, msg := range []string{flipped, enc + "\n", "k1." + strings.Repeat("A", 64)} {
				_, err = e.api.DecodeAuthorizationMessage(ctx, e.stsSign(auditor.id, auditor.secretKey, "", decodeAction), "", msg)
				wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "InvalidAuthorizationMessageException")
			}
			for _, msg := range []string{"", strings.Repeat("A", 10241)} {
				_, err = e.api.DecodeAuthorizationMessage(ctx, e.stsSign(auditor.id, auditor.secretKey, "", decodeAction), "", msg)
				wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
			}
			// No authentication at all.
			_, err = e.api.DecodeAuthorizationMessage(ctx, nil, "", enc)
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "MissingAuthenticationToken")

			// A console session authenticates too, until logout.
			const pw = "correct horse battery"
			lp := &iamv1.SetLoginProfileRequest{Name: auditor.user.GetName(), Password: pw}
			if _, err := e.users.SetLoginProfile(ctx, lp); err != nil {
				t.Fatal(err)
			}
			l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "auditor", Password: pw})
			if err != nil {
				t.Fatal(err)
			}
			viaConsole, err := e.api.DecodeAuthorizationMessage(ctx, nil, l.GetSessionToken(), enc)
			if err != nil || viaConsole != got {
				t.Fatalf("console: %v", err)
			}
			if _, err := e.auth.Logout(ctx, &iamv1.LogoutRequest{SessionToken: l.GetSessionToken()}); err != nil {
				t.Fatal(err)
			}
			_, err = e.api.DecodeAuthorizationMessage(ctx, nil, l.GetSessionToken(), enc)
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")
		})
	}
}

// TestDecodeAuthorizationMessageSourceIPDeny: the decode permission is
// evaluated with the caller's aws:SourceIp, from the SigV4 request or the
// console session, so an IP-conditioned explicit Deny refuses the decode.
func TestDecodeAuthorizationMessageSourceIPDeny(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			now := time.Now().UTC()
			e := newEnvOn(t, bk.open(), &now)
			ctx := t.Context()
			bob := e.keyedUser(t, "bob", `{"Version":"2012-10-17","Statement":[
				{"Sid":"NoDelete","Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`)
			auditor := e.keyedUser(t, "auditor", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"sts:DecodeAuthorizationMessage","Resource":"*"},
				{"Effect":"Deny","Action":"sts:DecodeAuthorizationMessage","Resource":"*",
				 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`)
			a, err := e.auth.Authenticate(ctx, e.sign(bob.id, bob.secretKey, ""))
			if err != nil {
				t.Fatal(err)
			}
			_, enc, err := e.api.AuthorizeEncoded(ctx, &iamv1.AuthorizeRequest{Principal: a.GetPrincipal(), Action: "s3:DeleteObject"})
			if err != nil || enc == "" {
				t.Fatalf("deny: %q %v", enc, err)
			}
			from := func(ip string) *iamv1.AuthenticateRequest {
				r := e.stsSign(auditor.id, auditor.secretKey, "", decodeAction)
				r.SourceIp = ip
				return r
			}
			_, err = e.api.DecodeAuthorizationMessage(ctx, from("10.1.2.3"), "", enc)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			if _, err := e.api.DecodeAuthorizationMessage(ctx, from("192.0.2.1"), "", enc); err != nil {
				t.Fatalf("outside the denied range: %v", err)
			}

			const pw = "correct horse battery"
			lp := &iamv1.SetLoginProfileRequest{Name: auditor.user.GetName(), Password: pw}
			if _, err := e.users.SetLoginProfile(ctx, lp); err != nil {
				t.Fatal(err)
			}
			for ip, deny := range map[string]bool{"10.9.9.9": true, "192.0.2.7": false} {
				l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "auditor", Password: pw, SourceIp: ip})
				if err != nil {
					t.Fatal(err)
				}
				_, err = e.api.DecodeAuthorizationMessage(ctx, nil, l.GetSessionToken(), enc)
				if deny {
					wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
				} else if err != nil {
					t.Fatalf("console from %s: %v", ip, err)
				}
			}
		})
	}
}
