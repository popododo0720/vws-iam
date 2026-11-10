package grpcapi_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

type unreadableBoundary struct{ store.Backend }

func (b unreadableBoundary) Get(ctx context.Context, k iam.Kind, key string) (store.Entry, error) {
	if k == iam.KindPolicy {
		return store.Entry{}, store.ErrUnavailable
	}
	return b.Backend.Get(ctx, k, key)
}

func TestAuthorizeUserPermissionsBoundary(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			sb := store.Scoped(b, proj)
			seedSim(t, b, func(u *iam.User) { u.PermissionsBoundary = simARN + "policy/Boundary" })
			boundary := iam.Policy{
				Meta: iam.Meta{UID: iam.NewUID()}, Name: "Boundary", ID: "ANPABOUNDARY",
				Created:        now,
				DefaultVersion: "v1",
				Versions:       []iam.PolicyVersion{{ID: "v1", Document: simDoc("s3:Get*"), Created: now}},
			}
			if _, err := store.Create(t.Context(), sb, boundary); err != nil {
				t.Fatal(err)
			}
			p := authz.Principal{Kind: authz.User, Name: "alice", ID: "AIDA1"}
			check := func(action string, allowed, explicit bool) {
				t.Helper()
				// Rebuild the authorizer each time, as a second replica or restart does.
				d, err := authz.New(sb, proj, func() time.Time { return now }).Authorize(t.Context(), p, action, "*", nil)
				if err != nil || d.Allowed != allowed || d.Explicit != explicit {
					t.Fatalf("%s: %+v, %v, want allowed=%t explicit=%t", action, d, err, allowed, explicit)
				}
			}
			check("s3:GetObject", true, false)
			check("ec2:RunInstances", false, false) // group allow cannot bypass a boundary
			check("s3:DeleteObject", false, true)
			p.SessionPolicies = []string{simDoc("s3:PutObject")}
			check("s3:GetObject", false, false)
			p.SessionPolicies = nil
			if _, err := store.Mutate(t.Context(), sb, "Boundary", func(pol *iam.Policy) error {
				pol.Versions[0].Document = `{"Statement":[
 {"Effect":"Allow","Action":"*","Resource":"*"},
 {"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]}`
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			check("s3:GetObject", false, true)
			e := newEnvOn(t, b, &now)
			if err := e.api.DeleteUserBoundary(t.Context(), proj, "alice"); err != nil {
				t.Fatal(err)
			}
			check("ec2:RunInstances", true, false)
			if _, err := store.Mutate(t.Context(), sb, "alice", func(u *iam.User) error {
				u.PermissionsBoundary = simARN + "policy/Missing"
				u.AttachedPolicies = nil
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			d, err := authz.New(sb, proj, nil).Authorize(t.Context(), p, "ec2:RunInstances", "*", nil)
			if !errors.Is(err, authz.ErrNoSuchEntity) || d.Allowed {
				t.Fatalf("missing boundary: %+v %v", d, err)
			}
			d, err = authz.New(unreadableBoundary{sb}, proj, nil).Authorize(t.Context(), p, "ec2:RunInstances", "*", nil)
			if !errors.Is(err, store.ErrUnavailable) || d.Allowed {
				t.Fatalf("unreadable boundary: %+v %v", d, err)
			}
		})
	}
}
