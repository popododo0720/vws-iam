package sts_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/sts"
)

// skews are the revoking replica's clock minus the issuing replica's:
// behind and ahead, inside and beyond sigv4.MaxSkew.
var skews = []time.Duration{-time.Hour, -10 * time.Minute, -time.Second, 0, time.Second, 10 * time.Minute, time.Hour}

// TestRevokeWithSkewedClocksMemstore runs the #46 suite on one shared
// in-memory backend.
func TestRevokeWithSkewedClocksMemstore(t *testing.T) {
	testRevokeSkew(t, func(*testing.T) store.Backend { return memstore.New() })
}

// TestRevokeWithSkewedClocksOnAPIServer runs it on kubestore against a
// real kube-apiserver with deploy/crds. It skips without KUBEBUILDER_ASSETS.
func TestRevokeWithSkewedClocksOnAPIServer(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set")
	}
	te := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "deploy", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := te.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := te.Stop(); err != nil {
			t.Error(err)
		}
	})
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	testRevokeSkew(t, func(t *testing.T) store.Backend {
		ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "vws-iam-"}}
		if err := c.Create(context.Background(), ns); err != nil {
			t.Fatal(err)
		}
		return kubestore.New(c, ns.Name)
	})
}

type replica struct {
	clk *clock
	svc *sts.Service
}

func testRevokeSkew(t *testing.T, backend func(*testing.T) store.Backend) {
	for _, d := range skews {
		t.Run("revoker"+d.String(), func(t *testing.T) {
			ctx := t.Context()
			b := backend(t)
			k := make([]byte, 32)
			if _, err := rand.Read(k); err != nil {
				t.Fatal(err)
			}
			keys, err := secret.NewKeyring("kek-1", map[string][]byte{"kek-1": k})
			if err != nil {
				t.Fatal(err)
			}
			put(t, b, iam.User{Name: "alice", ID: "1", InlinePolicies: map[string]string{"assume": assumeAny}})
			put(t, b, iam.Role{
				Name: "admin", ID: "4", MaxSessionDuration: 12 * time.Hour,
				AssumeRolePolicy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow",` +
					`"Principal":{"AWS":"arn:vws:iam::` + acct + `:user/alice"},"Action":"sts:AssumeRole"}}`,
			})
			base := time.Now().UTC()
			mk := func(off time.Duration) replica {
				clk := &clock{t: base.Add(off)}
				return replica{clk: clk, svc: sts.New(b, keys, authz.New(b, acct, clk.now), acct, clk.now)}
			}
			issuer, revoker := mk(0), mk(d)
			cred, err := accesskey.New(b, b, acct, keys, issuer.clk.now).Create(ctx, "alice")
			if err != nil {
				t.Fatal(err)
			}
			caller, err := issuer.svc.Resolve(ctx, sts.Credential{AccessKeyID: cred.AccessKeyID})
			if err != nil {
				t.Fatal(err)
			}
			issue := func(name string) (role, user sts.Credentials) {
				t.Helper()
				role, err := issuer.svc.AssumeRole(ctx, caller, nil, adminARN, name, 6*time.Hour, "", sts.MFA{})
				if err != nil {
					t.Fatal(err)
				}
				user, err = issuer.svc.GetSessionToken(ctx, caller, 0, sts.MFA{})
				if err != nil {
					t.Fatal(err)
				}
				return role, user
			}
			check := func(c sts.Credentials, wantValid bool, what string) {
				t.Helper()
				for _, r := range []replica{issuer, revoker} {
					_, err := r.svc.Validate(ctx, c.AccessKeyID, c.SessionToken)
					if wantValid && err != nil {
						t.Fatalf("%s: rejected: %v", what, err)
					}
					if !wantValid && !errors.Is(err, sts.ErrInvalidToken) {
						t.Fatalf("%s: err = %v, want InvalidClientTokenId", what, err)
					}
				}
			}

			// The issuer's clock ticks a little between issue and revoke,
			// far less than any skew.
			oldRole, oldUser := issue("before")
			issuer.clk.t = issuer.clk.t.Add(time.Millisecond)
			revoker.clk.t = revoker.clk.t.Add(time.Millisecond)
			if err := revoker.svc.RevokeSessions(ctx, authz.Role, "admin"); err != nil {
				t.Fatal(err)
			}
			if err := revoker.svc.RevokeSessions(ctx, authz.User, "alice"); err != nil {
				t.Fatal(err)
			}
			check(oldRole, false, "role session issued before revoke")
			check(oldUser, false, "user session issued before revoke")

			// Issued after the revoke committed: valid on every replica,
			// with no clock-based grace period, even when the revoker's
			// clock is ahead of the issuer's.
			newRole, newUser := issue("after")
			check(newRole, true, "role session issued after revoke")
			check(newUser, true, "user session issued after revoke")

			// sessions_revoke_time never moves backwards: a later revoke
			// from a replica whose clock is behind keeps the newer time.
			r1, err := store.Get[iam.Role](ctx, b, "admin")
			if err != nil {
				t.Fatal(err)
			}
			behind := mk(d - 2*time.Hour)
			if err := behind.svc.RevokeSessions(ctx, authz.Role, "admin"); err != nil {
				t.Fatal(err)
			}
			r2, err := store.Get[iam.Role](ctx, b, "admin")
			if err != nil {
				t.Fatal(err)
			}
			if !r2.Object.SessionsRevokedBefore.Equal(r1.Object.SessionsRevokedBefore) ||
				r2.Object.SessionsRevokeGeneration != r1.Object.SessionsRevokeGeneration+1 {
				t.Fatalf("revoke from a behind clock: time %v -> %v, gen %d -> %d",
					r1.Object.SessionsRevokedBefore, r2.Object.SessionsRevokedBefore,
					r1.Object.SessionsRevokeGeneration, r2.Object.SessionsRevokeGeneration)
			}
			check(newRole, false, "role session after the second revoke")
			check(newUser, true, "user session after a role-only revoke")
		})
	}
}
