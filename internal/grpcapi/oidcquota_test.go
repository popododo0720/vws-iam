package grpcapi_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func quotaOIDCURL(i int) string { return fmt.Sprintf("https://idp%03d.test", i) }

// fillOIDCProviders creates providers idp000 to idp<n-1> in project pid on e.
func fillOIDCProviders(t *testing.T, e *env, pid string, n int) {
	t.Helper()
	for i := range n {
		if _, err := e.api.CreateOpenIDConnectProvider(t.Context(), pid, quotaOIDCURL(i), nil, nil, nil); err != nil {
			t.Fatalf("provider %d of %d: %v", i+1, n, err)
		}
	}
}

func wantOIDCQuota(t *testing.T, err error) {
	t.Helper()
	wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
	want := "Cannot exceed quota for OpenIdConnectProvidersPerAccount: 100"
	if msg := status.Convert(err).Message(); msg != want {
		t.Fatalf("message %q, want %q", msg, want)
	}
}

// activeOIDC counts the providers of the project that are not pending.
func activeOIDC(t *testing.T, b store.Backend) int {
	t.Helper()
	all, err := store.List[iam.OIDCProvider](t.Context(), store.Scoped(b, proj))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, v := range all {
		if !v.Object.Pending {
			n++
		}
	}
	return n
}

// TestOIDCProvidersPerAccountQuota: a project holds at most 100 OpenID
// Connect providers. The 101st create is LimitExceeded and stores
// nothing, also on a replica started later; a URL already registered at
// the quota is still EntityAlreadyExists; another project has its own
// quota; once a provider is deleted a create succeeds again. On both
// store backends.
func TestOIDCProvidersPerAccountQuota(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			fillOIDCProviders(t, e, proj, iam.MaxOIDCProvidersPerAccount)
			_, err := e.api.CreateOpenIDConnectProvider(t.Context(), proj, "https://one-more.test", nil, nil, nil)
			wantOIDCQuota(t, err)
			replica := newEnvOn(t, b, &now)
			_, err = replica.api.CreateOpenIDConnectProvider(t.Context(), proj, "https://one-more.test", nil, nil, nil)
			wantOIDCQuota(t, err)
			_, err = replica.api.CreateOpenIDConnectProvider(t.Context(), proj, quotaOIDCURL(0), nil, nil, nil)
			wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			if n := oidcCount(t, b); n != iam.MaxOIDCProvidersPerAccount {
				t.Fatalf("%d providers stored, want %d", n, iam.MaxOIDCProvidersPerAccount)
			}
			list, err := replica.api.ListOpenIDConnectProviders(t.Context(), proj)
			if err != nil || len(list) != iam.MaxOIDCProvidersPerAccount {
				t.Fatalf("ListOpenIDConnectProviders: %d, %v", len(list), err)
			}
			_, err = e.api.CreateOpenIDConnectProvider(t.Context(), "other", "https://one-more.test", nil, nil, nil)
			if err != nil {
				t.Fatalf("another project's first provider: %v", err)
			}
			if err := replica.api.DeleteOpenIDConnectProvider(t.Context(), proj,
				"arn:vws:iam::"+proj+":oidc-provider/idp042.test"); err != nil {
				t.Fatal(err)
			}
			_, err = e.api.CreateOpenIDConnectProvider(t.Context(), proj, "https://one-more.test", nil, nil, nil)
			if err != nil {
				t.Fatalf("create after a delete freed a slot: %v", err)
			}
			_, err = replica.api.CreateOpenIDConnectProvider(t.Context(), proj, "https://two-more.test", nil, nil, nil)
			wantOIDCQuota(t, err)
		})
	}
}

// TestOIDCProvidersPerAccountConcurrent: with 98 providers stored, racing
// creates of distinct URLs on two replicas make exactly two more; every
// other is LimitExceeded. On both store backends.
func TestOIDCProvidersPerAccountConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			fillOIDCProviders(t, replicas[0], proj, iam.MaxOIDCProvidersPerAccount-2)
			errs := make([]error, 8)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					_, errs[i] = replicas[i%2].api.CreateOpenIDConnectProvider(t.Context(), proj,
						fmt.Sprintf("https://racer-%d.test", i), nil, nil, nil)
				})
			}
			wg.Wait()
			won := 0
			for _, err := range errs {
				if err == nil {
					won++
					continue
				}
				wantOIDCQuota(t, err)
			}
			if won != 2 {
				t.Fatalf("%d racing creates succeeded, want 2", won)
			}
			if n := activeOIDC(t, b); n != iam.MaxOIDCProvidersPerAccount {
				t.Fatalf("%d providers active, want %d", n, iam.MaxOIDCProvidersPerAccount)
			}
		})
	}
}

const pendingOIDCURL = "https://idp.test"

var pendingOIDCARN = "arn:vws:iam::" + proj + ":oidc-provider/idp.test"

// putPendingOIDC stores provider url of proj as a create that never
// committed would leave it.
func putPendingOIDC(t *testing.T, b store.Backend, url string) {
	t.Helper()
	op := iam.OIDCProvider{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, URL: url, Created: time.Now().UTC(),
		ClientIDs: []string{"left"}, Tags: map[string]string{"left": "behind"}, Pending: true,
	}
	if _, err := store.Create(t.Context(), store.Scoped(b, proj), op); err != nil {
		t.Fatal(err)
	}
}

// TestPendingOIDCProviderIsInert: a provider left pending (its create died
// or lost its hold before the commit) serves nothing: Get, the thumbprint,
// client id and tag calls and ListTags are NoSuchEntity, List leaves it
// out, and Delete succeeds, as for an unknown provider, without touching
// it. It does not count toward the quota, and the next create of its URL
// replaces it with that request's provider. On both store backends.
func TestPendingOIDCProviderIsInert(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			ctx := t.Context()
			putPendingOIDC(t, b, pendingOIDCURL)
			before := storedOIDC(t, b, iam.OIDCProviderKey(pendingOIDCURL))
			_, err := e.api.GetOpenIDConnectProvider(ctx, proj, pendingOIDCARN)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			err = e.api.UpdateOpenIDConnectProviderThumbprint(ctx, proj, pendingOIDCARN, []string{oidcThumbprint})
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			err = e.api.AddClientIDToOpenIDConnectProvider(ctx, proj, pendingOIDCARN, "app")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			err = e.api.RemoveClientIDFromOpenIDConnectProvider(ctx, proj, pendingOIDCARN, "left")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			err = e.api.TagOpenIDConnectProvider(ctx, proj, pendingOIDCARN, []*iamv1.Tag{samlTag("k", "v")})
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			err = e.api.UntagOpenIDConnectProvider(ctx, proj, pendingOIDCARN, []string{"left"})
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			_, err = e.api.ListOpenIDConnectProviderTags(ctx, proj, pendingOIDCARN, "", 0)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			if err := e.api.DeleteOpenIDConnectProvider(ctx, proj, pendingOIDCARN); err != nil {
				t.Fatalf("DeleteOpenIDConnectProvider of a pending provider: %v, want success", err)
			}
			if list, err := e.api.ListOpenIDConnectProviders(ctx, proj); err != nil || len(list) != 0 {
				t.Fatalf("ListOpenIDConnectProviders = %v, %v, want none", list, err)
			}
			if after := storedOIDC(t, b, iam.OIDCProviderKey(pendingOIDCURL)); after.Version != before.Version {
				t.Fatal("a call on the pending provider wrote it")
			}

			fillOIDCProviders(t, e, proj, iam.MaxOIDCProvidersPerAccount-1)
			created, err := e.api.CreateOpenIDConnectProvider(ctx, proj, pendingOIDCURL, []string{"app"}, nil, nil)
			if err != nil {
				t.Fatalf("the 100th create, over a pending provider of its URL: %v", err)
			}
			got := storedOIDC(t, b, iam.OIDCProviderKey(pendingOIDCURL)).Object
			if got.Pending || got.UID != created.Provider.UID || len(got.Tags) != 0 ||
				len(got.ClientIDs) != 1 || got.ClientIDs[0] != "app" {
				t.Fatalf("stored %+v, want the new request's active provider", got)
			}
			if _, err := e.api.GetOpenIDConnectProvider(ctx, proj, pendingOIDCARN); err != nil {
				t.Fatalf("GetOpenIDConnectProvider once the provider committed: %v", err)
			}
			_, err = e.api.CreateOpenIDConnectProvider(ctx, proj, "https://one-more.test", nil, nil, nil)
			wantOIDCQuota(t, err)
		})
	}
}

// TestPendingOIDCProviderOverQuota: a pending provider of a URL the
// project has no room for is refused LimitExceeded and stays pending.
func TestPendingOIDCProviderOverQuota(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	fillOIDCProviders(t, e, proj, iam.MaxOIDCProvidersPerAccount)
	putPendingOIDC(t, b, pendingOIDCURL)
	_, err := e.api.CreateOpenIDConnectProvider(t.Context(), proj, pendingOIDCURL, nil, nil, nil)
	wantOIDCQuota(t, err)
	if !storedOIDC(t, b, iam.OIDCProviderKey(pendingOIDCURL)).Object.Pending {
		t.Fatal("a refused create activated the pending provider")
	}
}

// TestOIDCProviderCreateLosesHold: a create whose lease runs out after it
// counted 99 providers and stored its pending provider, while another
// replica takes the lock and creates the 100th, cannot commit: it counts
// again under a new hold and is LimitExceeded, and its provider stays
// pending, so the project never holds 101. On both store backends.
func TestOIDCProviderCreateLosesHold(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			b := &stealBeforeActivate{Backend: inner, kind: iam.KindOIDCProvider}
			slow := newEnvOn(t, b, &now)
			fast := newEnvOn(t, b, &now)
			fillOIDCProviders(t, newEnvOn(t, inner, &now), proj, iam.MaxOIDCProvidersPerAccount-1)
			b.steal = func() {
				now = now.Add(membershipLease)
				_, err := fast.api.CreateOpenIDConnectProvider(t.Context(), proj, "https://fast.test", nil, nil, nil)
				if err != nil {
					t.Errorf("the create that took the lock: %v", err)
				}
			}
			_, err := slow.api.CreateOpenIDConnectProvider(t.Context(), proj, pendingOIDCURL, nil, nil, nil)
			wantOIDCQuota(t, err)
			if n := activeOIDC(t, inner); n != iam.MaxOIDCProvidersPerAccount {
				t.Fatalf("%d providers active, want %d", n, iam.MaxOIDCProvidersPerAccount)
			}
			if !storedOIDC(t, inner, iam.OIDCProviderKey(pendingOIDCURL)).Object.Pending {
				t.Fatal("the create that lost its hold committed its provider")
			}
			_, err = fast.api.GetOpenIDConnectProvider(t.Context(), proj, pendingOIDCARN)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
		})
	}
}

// TestOIDCProviderCreateCrash: a process that dies at any write of a
// create (the lock, the pending provider, the commit, the release), with
// the write lost or applied, leaves at most an inert pending provider.
// After the lease, the same request on a restarted replica makes the
// provider, or is EntityAlreadyExists when the commit had landed; either
// way exactly one active provider holds the request's client ids. On both
// store backends.
func TestOIDCProviderCreateCrash(t *testing.T) {
	for _, bk := range renameBackends {
		for _, lost := range []bool{false, true} {
			for n := 1; n <= 4; n++ {
				t.Run(fmt.Sprintf("%s/write%d/lost=%v", bk.name, n, lost), func(t *testing.T) {
					c := &crashing{Backend: bk.open()}
					now := time.Now().UTC()
					ids := []string{"crash"}
					c.arm(n, lost)
					_, first := newEnvOn(t, c, &now).api.CreateOpenIDConnectProvider(t.Context(), proj, pendingOIDCURL, ids, nil, nil)
					crashed := c.revive()
					if !crashed && first != nil {
						t.Fatalf("create without a crash: %v", first)
					}
					if active := activeOIDC(t, c); active > 1 {
						t.Fatalf("%d providers active after the crash", active)
					}
					now = now.Add(membershipLease)
					_, err := newEnvOn(t, c, &now).api.CreateOpenIDConnectProvider(t.Context(), proj, pendingOIDCURL, ids, nil, nil)
					if err != nil {
						wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
					}
					got := storedOIDC(t, c, iam.OIDCProviderKey(pendingOIDCURL)).Object
					if got.Pending || len(got.ClientIDs) != 1 || got.ClientIDs[0] != "crash" || activeOIDC(t, c) != 1 {
						t.Fatalf("after the retry: pending=%v, %d active, want one active provider with the client id",
							got.Pending, activeOIDC(t, c))
					}
				})
			}
		}
	}
}
