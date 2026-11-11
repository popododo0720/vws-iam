package grpcapi_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// TestSTSMFAThrottleMessage: a throttled STS-MFA attempt answers the
// client message it had before limiter errors carried step context
// (#305): the diagnostic step never reaches the wire.
func TestSTSMFAThrottleMessage(t *testing.T) {
	const want = "Throttling: too many failed attempts; try again later"
	now := time.Now().UTC()
	e := newEnvOn(t, memstore.New(), &now)
	ctx := t.Context()
	alice := e.keyedUser(t, "alice", `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}]}`)
	seed, serial, _ := strings.Cut(enableMFA(t, e, ctx, "alice"), "|")
	trust := `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:vws:iam::acme:user/alice"},"Action":"sts:AssumeRole"}]}`
	op, err := e.roles.CreateRole(ctx, &iamv1.CreateRoleRequest{
		Parent: parentName, RoleId: "deployer", Role: &iamv1.Role{Spec: &iamv1.RoleSpec{AssumeRolePolicy: trust}},
	})
	if err != nil {
		t.Fatal(err)
	}
	role := unpack(t, op, &iamv1.Role{}).GetName()
	calls := []struct {
		name string
		call func(code string) error
	}{
		{"GetSessionToken", func(code string) error {
			_, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
				Authentication: gstSig(e.stsSign(alice.id, alice.secretKey, "", "GetSessionToken")),
				SerialNumber:   serial, TokenCode: code,
			})
			return err
		}},
		{"AssumeRole", func(code string) error {
			_, err := e.token.AssumeRole(ctx, &iamv1.AssumeRoleRequest{
				Authentication: arSig(e.stsSign(alice.id, alice.secretKey, "", "AssumeRole")),
				Role:           role, RoleSessionName: "mfa", SerialNumber: serial, TokenCode: code,
			})
			return err
		}},
	}
	for range grpcapi.KeyAttemptLimit {
		wantErr(t, calls[0].call("000000"), codes.PermissionDenied, "ACCESS_DENIED", "AccessDenied")
	}
	now = now.Add(30 * time.Second)
	for _, c := range calls {
		err := c.call(code(t, e, seed))
		wantErr(t, err, codes.ResourceExhausted, "QUOTA_EXCEEDED", "Throttling")
		if got := status.Convert(err).Message(); got != want {
			t.Errorf("%s message = %q, want %q", c.name, got, want)
		}
	}
}
