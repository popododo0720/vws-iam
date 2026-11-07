package grpcapi_test

import (
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// TestAssumeRoleSourceIP: AssumeRole evaluates the caller's identity
// policy and the role's trust policy with the aws:SourceIp the server
// knows (the SigV4 request's address, or the address of the console
// Login), so an IP-conditioned Deny in either refuses the call, on both
// store backends and on a second server over the same store.
func TestAssumeRoleSourceIP(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			alice := e.keyedUser(t, "alice", `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"},
				{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*",
				 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`)
			trust := `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Principal":{"AWS":"arn:vws:iam::acme:user/alice"},"Action":"sts:AssumeRole"},
				{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"sts:AssumeRole",
				 "Condition":{"IpAddress":{"aws:SourceIp":"198.51.100.0/24"}}}]}`
			op, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
				Parent: parentName, RoleId: "deployer", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}},
			})
			if err != nil {
				t.Fatal(err)
			}
			role := unpack(t, op, &iamv1.Role{}).GetName()
			denied := map[string]bool{"10.1.2.3": true, "198.51.100.9": true, "192.0.2.1": false}

			for ip, deny := range denied {
				sig := e.stsSign(alice.id, alice.secretKey, "", "AssumeRole")
				sig.SourceIp = ip
				_, err := e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
					Authentication: arSig(sig), Role: role, RoleSessionName: "sig",
				})
				if deny {
					wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
				} else if err != nil {
					t.Fatalf("SigV4 from %s: %v", ip, err)
				}
			}

			const pw = "correct horse battery"
			lp := &iamv1.SetLoginProfileRequest{Name: alice.user.GetName(), Password: pw}
			if _, err := e.users.SetLoginProfile(ctx, lp); err != nil {
				t.Fatal(err)
			}
			tokens := map[string]string{}
			for ip := range denied {
				l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: pw, SourceIp: ip})
				if err != nil {
					t.Fatal(err)
				}
				tokens[ip] = l.GetSessionToken()
			}
			replica := newEnvOn(t, b, &now)
			for i, srv := range []iamv1.TokenServiceClient{e.token, replica.token} {
				for ip, deny := range denied {
					_, err := srv.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
						Authentication: &iamv1.AssumeRoleRequest_ConsoleSessionToken{ConsoleSessionToken: tokens[ip]},
						Role:           role, RoleSessionName: fmt.Sprintf("console-%d", i),
					})
					if deny {
						wantErr(t, err, codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
					} else if err != nil {
						t.Fatalf("server %d, console from %s: %v", i, ip, err)
					}
				}
			}
		})
	}
}
