package grpcapi_test

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"
)

// TestInvalidSessionTokenAWSCode pins the wire code of a session token that
// does not open: InvalidToken, the S3 code for a malformed token, not the
// unknown-access-key code (#132).
func TestInvalidSessionTokenAWSCode(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	u := e.createUser(t, ctx, "alice")
	key, err := e.keys.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: u.GetName()})
	if err != nil {
		t.Fatal(err)
	}
	kid := key.GetAccessKey().GetName()[strings.LastIndex(key.GetAccessKey().GetName(), "/")+1:]
	sess, err := e.token.GetSessionToken(ctx, &iamv1.GetSessionTokenRequest{
		Authentication: gstSig(e.stsSign(kid, key.GetSecretAccessKey(), "", "GetSessionToken")),
	})
	if err != nil {
		t.Fatal(err)
	}
	c := sess.GetCredentials()

	_, err = e.auth.Authenticate(ctx, e.sign(c.GetAccessKeyId(), c.GetSecretAccessKey(), "not-a-session-token"))
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidToken")

	// An unknown access key keeps its own code, which is what makes the
	// two failures tellable apart.
	_, err = e.auth.Authenticate(ctx, e.sign("AKIAAAAAAAAAAAAAAAAA", c.GetSecretAccessKey(), ""))
	wantErr(t, err, codes.Unauthenticated, "INVALID_CREDENTIALS", "InvalidClientTokenId")

	// Expiry keeps its own code; it does not become InvalidToken.
	*e.now = e.now.Add(13 * time.Hour)
	_, err = e.auth.Authenticate(ctx, e.sign(c.GetAccessKeyId(), c.GetSecretAccessKey(), c.GetSessionToken()))
	wantErr(t, err, codes.Unauthenticated, "TOKEN_EXPIRED", "ExpiredToken")
}
