package grpcapi_test

import (
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// TestLoginMFARacingRenameMark: Login reads alice before a rename marks
// her, then the rename moves her MFA device to bob before Login lists
// devices. Login must not issue a password-only session that the rename
// later hands to bob.
func TestLoginMFARacingRenameMark(t *testing.T) {
	for _, bc := range renameBackends {
		t.Run(bc.name, func(t *testing.T) {
			h := &hooked{Backend: bc.open()}
			now := time.Now().UTC()
			e := newEnvOn(t, h, &now)
			ctx := t.Context()
			e.createUser(t, ctx, "alice")
			e.setPassword(t, ctx, "alice", testPassword)
			enableMFA(t, e, ctx, "alice")
			ran := false
			h.at("list", iam.KindMfaDevice, "", func() error {
				ran = true
				markRename(t, h, "alice", "bob", now)
				pb := store.Scoped(h, proj)
				d, err := store.Get[iam.MfaDevice](ctx, pb, "alice-phone")
				if err != nil {
					t.Fatal(err)
				}
				d.Object.UserName = "bob"
				if _, err := store.Update(ctx, pb, d.Object, d.Version); err != nil {
					t.Fatal(err)
				}
				return nil
			})
			l, err := e.auth.Login(ctx, &iamv1.LoginRequest{Project: proj, UserName: "alice", Password: testPassword})
			if !ran {
				t.Fatal("the hook did not run")
			}
			if err == nil {
				// Finish the rename: it moves the session to bob.
				*e.now = e.now.Add(2 * time.Minute)
				if _, rerr := e.api.ResumeRenames(ctx); rerr != nil {
					t.Fatal(rerr)
				}
				v, verr := e.auth.ValidateSession(ctx, &iamv1.ValidateSessionRequest{SessionToken: l.GetSessionToken()})
				t.Fatalf("Login issued a session without MFA (mfa=%v); after the rename it validates as %v (%v)",
					l.GetPrincipal().GetMfaAuthenticated(), v.GetPrincipal().GetResource(), verr)
			}
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
		})
	}
}
