package grpcapi_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
)

const keyInfoAction = "GetAccessKeyInfo"

// TestGetAccessKeyInfo: a caller allowed sts:GetAccessKeyInfo learns the
// project of a key of its own or another project, through SigV4 or a
// console session, on any replica, on both store backends; everything
// else is refused with the AWS error.
func TestGetAccessKeyInfo(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			bob := e.keyedUser(t, "bob", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
			auditor := e.keyedUser(t, "auditor", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"sts:GetAccessKeyInfo","Resource":"*"},
				{"Effect":"Deny","Action":"sts:GetAccessKeyInfo","Resource":"*",
				 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`)
			// A key of another project in the same store.
			kr, err := secret.NewKeyring("k1", map[string][]byte{"k1": make([]byte, 32)})
			if err != nil {
				t.Fatal(err)
			}
			ob := store.Scoped(b, "globex")
			if _, err := store.Create(ctx, ob, iam.User{Name: "carol", ID: "AIDACAROL"}); err != nil {
				t.Fatal(err)
			}
			theirs, err := accesskey.New(ob, b, "globex", kr, nil).Create(ctx, "carol")
			if err != nil {
				t.Fatal(err)
			}

			sign := func() *iamv1.AuthenticateRequest {
				return e.stsSign(auditor.id, auditor.secretKey, "", keyInfoAction)
			}
			for id, want := range map[string]string{bob.id: proj, theirs.AccessKeyID: "globex"} {
				got, err := e.api.GetAccessKeyInfo(ctx, sign(), "", "", id)
				if err != nil || got != want {
					t.Fatalf("GetAccessKeyInfo(%s) = %q, %v; want %q", id, got, err, want)
				}
			}
			// Another replica answers the same.
			replica := newEnvOn(t, b, &now)
			replica.nonce = 1000
			r := replica.stsSign(auditor.id, auditor.secretKey, "", keyInfoAction)
			if got, err := replica.api.GetAccessKeyInfo(ctx, r, "", "", theirs.AccessKeyID); err != nil || got != "globex" {
				t.Fatalf("replica: %q, %v", got, err)
			}

			// The same signed request cannot be used twice, and a request
			// signed for another STS action is refused.
			once := sign()
			if _, err := e.api.GetAccessKeyInfo(ctx, once, "", "", bob.id); err != nil {
				t.Fatal(err)
			}
			_, err = e.api.GetAccessKeyInfo(ctx, once, "", "", bob.id)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			_, err = e.api.GetAccessKeyInfo(ctx, e.stsSign(auditor.id, auditor.secretKey, "", "AssumeRole"), "", "", bob.id)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")

			// No permission: AccessDenied even for an existing key.
			_, err = e.api.GetAccessKeyInfo(ctx, e.stsSign(bob.id, bob.secretKey, "", keyInfoAction), "", "", theirs.AccessKeyID)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
			// An IP-conditioned Deny applies to the SigV4 address.
			from := sign()
			from.SourceIp = "10.1.2.3"
			_, err = e.api.GetAccessKeyInfo(ctx, from, "", "", bob.id)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")

			// Unknown and malformed key ids.
			_, err = e.api.GetAccessKeyInfo(ctx, sign(), "", "", "AKIA"+strings.Repeat("A", 16))
			wantErr(t, err, codes.NotFound, "RESOURCE_NOT_FOUND", "InvalidClientTokenId")
			for _, id := range []string{"", strings.Repeat("A", 15), strings.Repeat("A", 129), "AKIA-AAAAAAAAAAAAAAA"} {
				_, err = e.api.GetAccessKeyInfo(ctx, sign(), "", "", id)
				wantErr(t, err, codes.InvalidArgument, "INVALID_SPEC", "ValidationError")
			}
			// No authentication at all.
			_, err = e.api.GetAccessKeyInfo(ctx, nil, "", "", bob.id)
			wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "MissingAuthenticationToken")

			// A console session authenticates too; the Deny applies to the
			// address the gateway saw for this request.
			const pw = "correct horse battery"
			lp := &iamv1.SetLoginProfileRequest{Name: auditor.user.GetName(), Password: pw}
			if _, err := e.users.SetLoginProfile(ctx, lp); err != nil {
				t.Fatal(err)
			}
			l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "auditor", Password: pw})
			if err != nil {
				t.Fatal(err)
			}
			got, err := e.api.GetAccessKeyInfo(ctx, nil, l.GetSessionToken(), "192.0.2.1", theirs.AccessKeyID)
			if err != nil || got != "globex" {
				t.Fatalf("console: %q, %v", got, err)
			}
			_, err = e.api.GetAccessKeyInfo(ctx, nil, l.GetSessionToken(), "10.9.9.9", theirs.AccessKeyID)
			wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
		})
	}
}
