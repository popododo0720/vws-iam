package grpcapi_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/store/storetest"
)

var quotaDoc = storetest.SAMLMetadata(strings.Repeat(" ", 100))

// fillSAMLProviders creates providers p000 to p<n-1> in project pid on e.
func fillSAMLProviders(t *testing.T, e *env, pid string, n int) {
	t.Helper()
	for i := range n {
		if _, err := e.api.CreateSAMLProvider(t.Context(), pid, fmt.Sprintf("p%03d", i), quotaDoc, nil); err != nil {
			t.Fatalf("provider %d of %d: %v", i+1, n, err)
		}
	}
}

func wantSAMLQuota(t *testing.T, err error) {
	t.Helper()
	wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
	if msg, want := status.Convert(err).Message(), "Cannot exceed quota for SAMLProvidersPerAccount: 100"; msg != want {
		t.Fatalf("message %q, want %q", msg, want)
	}
}

// activeSAML counts the providers of the project that are not pending.
func activeSAML(t *testing.T, b store.Backend) int {
	t.Helper()
	all, err := store.List[iam.SAMLProvider](t.Context(), store.Scoped(b, proj))
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

// TestSAMLProvidersPerAccountQuota: a project holds at most 100 SAML
// providers. The 101st create is LimitExceeded and stores nothing, also
// on a replica started later; a taken name at the quota is still
// EntityAlreadyExists; another project has its own quota; once a provider
// is deleted a create succeeds again. On both store backends.
func TestSAMLProvidersPerAccountQuota(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			fillSAMLProviders(t, e, proj, iam.MaxSAMLProvidersPerAccount)
			_, err := e.api.CreateSAMLProvider(t.Context(), proj, "one-more", quotaDoc, nil)
			wantSAMLQuota(t, err)
			replica := newEnvOn(t, b, &now)
			_, err = replica.api.CreateSAMLProvider(t.Context(), proj, "one-more", quotaDoc, nil)
			wantSAMLQuota(t, err)
			_, err = replica.api.CreateSAMLProvider(t.Context(), proj, "P000", quotaDoc, nil)
			wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			if n := samlCount(t, b); n != iam.MaxSAMLProvidersPerAccount {
				t.Fatalf("%d providers stored, want %d", n, iam.MaxSAMLProvidersPerAccount)
			}
			list, err := replica.api.ListSAMLProviders(t.Context(), proj)
			if err != nil || len(list) != iam.MaxSAMLProvidersPerAccount {
				t.Fatalf("ListSAMLProviders: %d, %v", len(list), err)
			}
			if _, err := e.api.CreateSAMLProvider(t.Context(), "other", "one-more", quotaDoc, nil); err != nil {
				t.Fatalf("another project's first provider: %v", err)
			}
			if err := replica.api.DeleteSAMLProvider(t.Context(), proj, "arn:vws:iam::"+proj+":saml-provider/p042"); err != nil {
				t.Fatal(err)
			}
			if _, err := e.api.CreateSAMLProvider(t.Context(), proj, "one-more", quotaDoc, nil); err != nil {
				t.Fatalf("create after a delete freed a slot: %v", err)
			}
			_, err = replica.api.CreateSAMLProvider(t.Context(), proj, "two-more", quotaDoc, nil)
			wantSAMLQuota(t, err)
		})
	}
}

// TestSAMLProvidersPerAccountConcurrent: with 98 providers stored, racing
// creates of distinct names on two replicas make exactly two more; every
// other is LimitExceeded. On both store backends.
func TestSAMLProvidersPerAccountConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			fillSAMLProviders(t, replicas[0], proj, iam.MaxSAMLProvidersPerAccount-2)
			errs := make([]error, 8)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					_, errs[i] = replicas[i%2].api.CreateSAMLProvider(t.Context(), proj, fmt.Sprintf("racer-%d", i), quotaDoc, nil)
				})
			}
			wg.Wait()
			won := 0
			for _, err := range errs {
				if err == nil {
					won++
					continue
				}
				wantSAMLQuota(t, err)
			}
			if won != 2 {
				t.Fatalf("%d racing creates succeeded, want 2", won)
			}
			if n := activeSAML(t, b); n != iam.MaxSAMLProvidersPerAccount {
				t.Fatalf("%d providers active, want %d", n, iam.MaxSAMLProvidersPerAccount)
			}
		})
	}
}

// putPending stores provider name of proj as a create that never
// committed would leave it.
func putPending(t *testing.T, b store.Backend, name, doc string) {
	t.Helper()
	sp := iam.SAMLProvider{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: name, Created: time.Now().UTC(),
		MetadataDocument: doc, Tags: map[string]string{"left": "behind"}, Pending: true,
	}
	if _, err := store.Create(t.Context(), store.Scoped(b, proj), sp); err != nil {
		t.Fatal(err)
	}
}

// TestPendingSAMLProviderIsInert: a provider left pending (its create died
// or lost its hold before the commit) serves nothing: AssumeRoleWithSAML
// refuses it, Get, Update, Tag, ListTags and Delete are NoSuchEntity and
// List leaves it out. It does not count toward the quota, and the next
// create of its name replaces it with that request's provider. On both
// store backends.
func TestPendingSAMLProviderIsInert(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			f := newSAMLFixture(t, bk.open())
			doc := f.idp.Metadata(f.now.Add(time.Hour))
			putPending(t, f.b, "corp", doc)
			e := f.server(t)
			ctx := t.Context()
			_, err := e.api.AssumeRoleWithSAML(ctx, f.signed(t, f.idp))
			wantAWS(t, err, codes.InvalidArgument, "InvalidIdentityToken")
			_, err = e.api.GetSAMLProvider(ctx, proj, samlIdpARN)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			_, err = e.api.UpdateSAMLProvider(ctx, proj, samlIdpARN, doc)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			err = e.api.TagSAMLProvider(ctx, proj, samlIdpARN, []*iamv1.Tag{samlTag("k", "v")})
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			_, err = e.api.ListSAMLProviderTags(ctx, proj, samlIdpARN, "", 0)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			err = e.api.DeleteSAMLProvider(ctx, proj, samlIdpARN)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			if list, err := e.api.ListSAMLProviders(ctx, proj); err != nil || len(list) != 0 {
				t.Fatalf("ListSAMLProviders = %v, %v, want none", list, err)
			}

			fillSAMLProviders(t, e, proj, iam.MaxSAMLProvidersPerAccount-1)
			created, err := e.api.CreateSAMLProvider(ctx, proj, "corp", doc, nil)
			if err != nil {
				t.Fatalf("the 100th create, over a pending provider of its name: %v", err)
			}
			got := storedSAML(t, f.b, "corp").Object
			if got.Pending || got.UID != created.Provider.UID || len(got.Tags) != 0 {
				t.Fatalf("stored %+v, want the new request's active provider", got)
			}
			if _, err := e.api.AssumeRoleWithSAML(ctx, f.signed(t, f.idp)); err != nil {
				t.Fatalf("AssumeRoleWithSAML once the provider committed: %v", err)
			}
			_, err = e.api.CreateSAMLProvider(ctx, proj, "one-more", quotaDoc, nil)
			wantSAMLQuota(t, err)
		})
	}
}

// TestPendingSAMLProviderOverQuota: a pending provider of a name the
// project has no room for is refused LimitExceeded and stays pending.
func TestPendingSAMLProviderOverQuota(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	fillSAMLProviders(t, e, proj, iam.MaxSAMLProvidersPerAccount)
	putPending(t, b, "late", quotaDoc)
	_, err := e.api.CreateSAMLProvider(t.Context(), proj, "late", quotaDoc, nil)
	wantSAMLQuota(t, err)
	if !storedSAML(t, b, "late").Object.Pending {
		t.Fatal("a refused create activated the pending provider")
	}
}

// stealBeforeActivate runs steal once, just before the first commit of a
// provider of kind (its UpdateIf), as a writer whose lease ran out would
// see another writer take the lock.
type stealBeforeActivate struct {
	store.Backend
	kind  iam.Kind
	steal func()
}

func (s *stealBeforeActivate) UpdateIf(
	ctx context.Context, k iam.Kind, key string, spec []byte, version string, pre store.Pre,
) (string, error) {
	if steal := s.steal; k == s.kind && steal != nil {
		s.steal = nil // the stealing create commits through here too
		steal()
	}
	return s.Backend.UpdateIf(ctx, k, key, spec, version, pre)
}

// TestSAMLProviderCreateLosesHold: a create whose lease runs out after it
// counted 99 providers and stored its pending provider, while another
// replica takes the lock and creates the 100th, cannot commit: it counts
// again under a new hold and is LimitExceeded, and its provider stays
// pending, so the project never holds 101. On both store backends.
func TestSAMLProviderCreateLosesHold(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			b := &stealBeforeActivate{Backend: inner, kind: iam.KindSAMLProvider}
			slow := newEnvOn(t, b, &now)
			fast := newEnvOn(t, b, &now)
			fillSAMLProviders(t, newEnvOn(t, inner, &now), proj, iam.MaxSAMLProvidersPerAccount-1)
			b.steal = func() {
				now = now.Add(membershipLease)
				if _, err := fast.api.CreateSAMLProvider(t.Context(), proj, "fast", quotaDoc, nil); err != nil {
					t.Errorf("the create that took the lock: %v", err)
				}
			}
			_, err := slow.api.CreateSAMLProvider(t.Context(), proj, "slow", quotaDoc, nil)
			wantSAMLQuota(t, err)
			if n := activeSAML(t, inner); n != iam.MaxSAMLProvidersPerAccount {
				t.Fatalf("%d providers active, want %d", n, iam.MaxSAMLProvidersPerAccount)
			}
			if !storedSAML(t, inner, "slow").Object.Pending {
				t.Fatal("the create that lost its hold committed its provider")
			}
			_, err = fast.api.GetSAMLProvider(t.Context(), proj, "arn:vws:iam::"+proj+":saml-provider/slow")
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
		})
	}
}

// TestSAMLProviderCreateCrash: a process that dies at any write of a
// create (the lock, the pending provider, the commit, the release), with
// the write lost or applied, leaves at most an inert pending provider.
// After the lease, the same request on a restarted replica makes the
// provider, or is EntityAlreadyExists when the commit had landed; either
// way exactly one active provider holds the request's document. On both
// store backends.
func TestSAMLProviderCreateCrash(t *testing.T) {
	for _, bk := range renameBackends {
		for _, lost := range []bool{false, true} {
			for n := 1; n <= 4; n++ {
				t.Run(fmt.Sprintf("%s/write%d/lost=%v", bk.name, n, lost), func(t *testing.T) {
					c := &crashing{Backend: bk.open()}
					now := time.Now().UTC()
					doc := storetest.SAMLMetadata("crash" + strings.Repeat(" ", 100))
					c.arm(n, lost)
					_, first := newEnvOn(t, c, &now).api.CreateSAMLProvider(t.Context(), proj, "corp", doc, nil)
					crashed := c.revive()
					if !crashed && first != nil {
						t.Fatalf("create without a crash: %v", first)
					}
					if active := activeSAML(t, c); active > 1 {
						t.Fatalf("%d providers active after the crash", active)
					}
					now = now.Add(membershipLease)
					_, err := newEnvOn(t, c, &now).api.CreateSAMLProvider(t.Context(), proj, "corp", doc, nil)
					if err != nil {
						wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
					}
					got := storedSAML(t, c, "corp").Object
					if got.Pending || got.MetadataDocument != doc || activeSAML(t, c) != 1 {
						t.Fatalf("after the retry: pending=%v, %d active, want one active provider with the document",
							got.Pending, activeSAML(t, c))
					}
				})
			}
		}
	}
}
