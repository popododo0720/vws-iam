package grpcapi_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func oidcARN(pid, url string) string {
	return "arn:vws:iam::" + pid + ":oidc-provider/" + strings.TrimPrefix(url, "https://")
}

func createOIDC(t *testing.T, e *env, pid, url string) {
	t.Helper()
	if _, err := e.api.CreateOpenIDConnectProvider(t.Context(), pid, url, []string{"app"}, nil, nil); err != nil {
		t.Fatal(err)
	}
}

func oidcGone(t *testing.T, b store.Backend, url string) {
	t.Helper()
	_, err := store.Get[iam.OIDCProvider](t.Context(), store.Scoped(b, proj), iam.OIDCProviderKey(url))
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("provider %s: %v, want deleted", url, err)
	}
}

// TestGetOpenIDConnectProvider: a provider is returned as stored, with
// its ARN, by a replica started later on the same store. An ARN that
// differs only in case names another issuer and is NoSuchEntity, as are
// an unknown provider and the same URL under another account. On both
// store backends.
func TestGetOpenIDConnectProvider(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 9, 5, 0, 0, 0, time.UTC)
			e := newEnvOn(t, b, &now)
			const url = "https://IdP.test/Team"
			made, err := e.api.CreateOpenIDConnectProvider(t.Context(), proj, url,
				[]string{"sts.amazonaws.com"}, []string{oidcThumbprint}, nil)
			if err != nil {
				t.Fatal(err)
			}
			replica := newEnvOn(t, b, &now)
			got, err := replica.api.GetOpenIDConnectProvider(t.Context(), proj, oidcARN(proj, url))
			if err != nil {
				t.Fatal(err)
			}
			p := got.Provider
			if got.ARN != made.ARN || p.UID != made.Provider.UID || p.URL != url || !p.Created.Equal(now) ||
				!slices.Equal(p.ClientIDs, []string{"sts.amazonaws.com"}) ||
				!slices.Equal(p.Thumbprints, []string{oidcThumbprint}) {
				t.Fatalf("GetOpenIDConnectProvider = %+v, want %+v", got, made)
			}
			if r := iam.OIDCProviderResource(p.URL); r != "IdP.test/Team" {
				t.Fatalf("Url element %q, want the URL without https://", r)
			}
			createOIDC(t, e, "other", "https://only.other.test")
			for _, arn := range []string{
				oidcARN(proj, "https://idp.test/team"),
				oidcARN(proj, "https://IdP.test/team"),
				oidcARN(proj, "https://unknown.test"),
				oidcARN("other", url),
				oidcARN(proj, "https://only.other.test"),
			} {
				_, err := replica.api.GetOpenIDConnectProvider(t.Context(), proj, arn)
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
		})
	}
}

// TestListOpenIDConnectProviders: no provider is an empty list; the ARNs
// of the project's providers, URLs differing only in case included, are
// listed once each in byte order, and another project's are not. On both
// store backends.
func TestListOpenIDConnectProviders(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			got, err := e.api.ListOpenIDConnectProviders(t.Context(), proj)
			if err != nil || got == nil || len(got) != 0 {
				t.Fatalf("ListOpenIDConnectProviders = %v, %v; want an empty list", got, err)
			}
			urls := []string{"https://b.test", "https://a.test/x", "https://A.test/x", "https://a.test"}
			for _, url := range urls {
				createOIDC(t, e, proj, url)
			}
			createOIDC(t, e, "other", "https://c.test")
			got, err = newEnvOn(t, b, &now).api.ListOpenIDConnectProviders(t.Context(), proj)
			if err != nil {
				t.Fatal(err)
			}
			want := []string{
				oidcARN(proj, "https://A.test/x"), oidcARN(proj, "https://a.test"),
				oidcARN(proj, "https://a.test/x"), oidcARN(proj, "https://b.test"),
			}
			if !slices.Equal(got, want) {
				t.Fatalf("ListOpenIDConnectProviders = %v, want %v", got, want)
			}
		})
	}
}

// TestDeleteOpenIDConnectProvider: a provider deleted on one replica is
// gone on another; a repeat, an unknown provider and an ARN of another
// account succeed without a write, as AWS documents the call idempotent;
// the provider of a URL differing only in case and the same URL in another
// project stay; the URL can be registered again. On both store backends.
func TestDeleteOpenIDConnectProvider(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			const url = "https://idp.test/Team"
			for _, u := range []string{url, "https://idp.test/team"} {
				createOIDC(t, e, proj, u)
			}
			createOIDC(t, e, "other", url)
			kept := storedOIDC(t, b, iam.OIDCProviderKey("https://idp.test/team"))
			if err := e.api.DeleteOpenIDConnectProvider(t.Context(), proj, oidcARN(proj, url)); err != nil {
				t.Fatal(err)
			}
			oidcGone(t, b, url)
			replica := newEnvOn(t, b, &now)
			_, err := replica.api.GetOpenIDConnectProvider(t.Context(), proj, oidcARN(proj, url))
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			for _, arn := range []string{oidcARN(proj, url), oidcARN(proj, "https://unknown.test"), oidcARN("other", url)} {
				if err := replica.api.DeleteOpenIDConnectProvider(t.Context(), proj, arn); err != nil {
					t.Fatalf("delete %s: %v, want success without a write", arn, err)
				}
			}
			if again := storedOIDC(t, b, iam.OIDCProviderKey("https://idp.test/team")); again.Version != kept.Version {
				t.Fatal("deleting another URL changed the provider differing only in case")
			}
			if _, err := replica.api.GetOpenIDConnectProvider(t.Context(), "other", oidcARN("other", url)); err != nil {
				t.Fatalf("the other project's provider: %v, want kept", err)
			}
			createOIDC(t, replica, proj, url)
		})
	}
}

// TestDeleteOpenIDConnectProviderConcurrent: racing deletes of one
// provider on two replicas all succeed and the provider is gone. On both
// store backends.
func TestDeleteOpenIDConnectProviderConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			const url = "https://race.test"
			createOIDC(t, replicas[0], proj, url)
			errs := make([]error, 16)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.DeleteOpenIDConnectProvider(t.Context(), proj, oidcARN(proj, url))
				})
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Errorf("delete %d: %v", i, err)
				}
			}
			oidcGone(t, b, url)
		})
	}
}

// changingOIDCBeforeDelete writes each OIDC provider before its next n
// deletes, so those deletes are at a stale version.
type changingOIDCBeforeDelete struct {
	store.Backend
	mu sync.Mutex
	n  int
	t  *testing.T
}

func (c *changingOIDCBeforeDelete) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if k == iam.KindOIDCProvider {
		c.mu.Lock()
		change := c.n > 0
		c.n--
		c.mu.Unlock()
		if change {
			b, name := store.Scoped(c.Backend, proj), strings.TrimPrefix(key, proj+"/")
			if _, err := store.Mutate(ctx, b, name, func(p *iam.OIDCProvider) error {
				p.ClientIDs = append(p.ClientIDs, "late-"+p.Created.Format(time.RFC3339Nano))
				p.Created = p.Created.Add(time.Second)
				return nil
			}); err != nil {
				c.t.Error(err)
			}
		}
	}
	return c.Backend.Delete(ctx, k, key, version)
}

// TestDeleteOpenIDConnectProviderStaleRead: a provider written after it
// was read is read again and then deleted, never deleted blind at a stale
// version; one that keeps changing is ConcurrentModification and stays.
// On both store backends.
func TestDeleteOpenIDConnectProviderStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seed := newEnvOn(t, inner, &now)
			for _, url := range []string{"https://once.test", "https://busy.test"} {
				createOIDC(t, seed, proj, url)
			}
			b := &changingOIDCBeforeDelete{Backend: inner, n: 1, t: t}
			if err := newEnvOn(t, b, &now).api.DeleteOpenIDConnectProvider(t.Context(), proj,
				oidcARN(proj, "https://once.test")); err != nil {
				t.Fatalf("delete after one concurrent write: %v, want deleted", err)
			}
			oidcGone(t, inner, "https://once.test")

			b = &changingOIDCBeforeDelete{Backend: inner, n: 1 << 30, t: t}
			err := newEnvOn(t, b, &now).api.DeleteOpenIDConnectProvider(t.Context(), proj, oidcARN(proj, "https://busy.test"))
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			storedOIDC(t, inner, iam.OIDCProviderKey("https://busy.test"))
		})
	}
}

// TestDeleteOpenIDConnectProviderCanceled: a canceled delete deletes
// nothing, and the same request afterwards deletes the provider.
func TestDeleteOpenIDConnectProviderCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	const url = "https://idp.test"
	createOIDC(t, e, proj, url)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.api.DeleteOpenIDConnectProvider(canceled, proj, oidcARN(proj, url)); err == nil {
		t.Fatal("a canceled delete succeeded")
	}
	storedOIDC(t, b, iam.OIDCProviderKey(url))
	if err := e.api.DeleteOpenIDConnectProvider(t.Context(), proj, oidcARN(proj, url)); err != nil {
		t.Fatalf("the same request afterwards: %v", err)
	}
	oidcGone(t, b, url)
}

// TestOIDCProviderARNErrors: Get and Delete answer a bad project or an ARN
// outside 20 to 2048 characters with ValidationError and an ARN that is
// not an OIDC provider ARN with InvalidInput, before any store access (the
// store here fails every read), never echoing the ARN; the longest URL's
// ARN is accepted. Nothing is deleted.
func TestOIDCProviderARNErrors(t *testing.T) {
	inner := memstore.New()
	now := time.Now().UTC()
	createOIDC(t, newEnvOn(t, inner, &now), proj, "https://idp.test")
	down := newEnvOn(t, failingGet{Backend: inner, k: iam.KindOIDCProvider, err: store.ErrUnavailable}, &now)
	const canary = "CANARY"
	prefix := "arn:vws:iam::" + proj + ":oidc-provider/"
	host := "https://" + strings.Repeat("a", 63)
	longest := host + "/" + strings.Repeat("b", iam.MaxOIDCProviderURLLen-len(host)-1)
	cases := []struct {
		name, pid, arn string
		aws            string
	}{
		{"bad project", "Bad_Project", oidcARN(proj, "https://idp.test"), "ValidationError"},
		{"ARN of 19 characters", proj, strings.Repeat("a", 19), "ValidationError"},
		{"ARN of 2049 characters", proj, prefix + strings.Repeat("a", 2049-len(prefix)), "ValidationError"},
		{"SAML provider ARN", proj, "arn:vws:iam::" + proj + ":saml-provider/" + canary, "InvalidInput"},
		{"other partition", proj, "arn:aws:iam::" + proj + ":oidc-provider/" + canary + ".test", "InvalidInput"},
		{"bad account", proj, "arn:vws:iam::Bad_" + canary + ":oidc-provider/idp.test", "InvalidInput"},
		{"no host", proj, prefix + "/" + canary, "InvalidInput"},
		{"host with a port", proj, prefix + canary + ".test:443", "InvalidInput"},
		{"query", proj, prefix + "idp.test/?" + canary, "InvalidInput"},
		{"bad escape", proj, prefix + "idp.test/%zz" + canary, "InvalidInput"},
		{"URL of 256 characters", proj, oidcARN(proj, longest+"b"), "InvalidInput"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := down.api.GetOpenIDConnectProvider(t.Context(), c.pid, c.arn)
			wantAWS(t, err, codes.InvalidArgument, c.aws)
			if strings.Contains(status.Convert(err).Message(), canary) {
				t.Fatalf("message carries the ARN: %q", status.Convert(err).Message())
			}
			err = down.api.DeleteOpenIDConnectProvider(t.Context(), c.pid, c.arn)
			wantAWS(t, err, codes.InvalidArgument, c.aws)
		})
	}
	_, err := down.api.GetOpenIDConnectProvider(t.Context(), proj, oidcARN(proj, longest))
	wantAWS(t, err, codes.Unavailable, "ServiceUnavailable")
	storedOIDC(t, inner, iam.OIDCProviderKey("https://idp.test"))
}

// TestOIDCProviderStoreFailures: a failed read or list is ServiceFailure
// (ServiceUnavailable when the store is unavailable), never NoSuchEntity
// or success, and a failed delete is ServiceFailure and keeps the
// provider.
func TestOIDCProviderStoreFailures(t *testing.T) {
	inner := memstore.New()
	now := time.Now().UTC()
	const url = "https://idp.test"
	createOIDC(t, newEnvOn(t, inner, &now), proj, url)
	arn := oidcARN(proj, url)
	for _, c := range []struct {
		err  error
		code codes.Code
		aws  string
	}{
		{errors.New("boom"), codes.Internal, "ServiceFailure"},
		{store.ErrUnavailable, codes.Unavailable, "ServiceUnavailable"},
	} {
		get := newEnvOn(t, failingGet{Backend: inner, k: iam.KindOIDCProvider, err: c.err}, &now)
		_, err := get.api.GetOpenIDConnectProvider(t.Context(), proj, arn)
		wantAWS(t, err, c.code, c.aws)
		wantAWS(t, get.api.DeleteOpenIDConnectProvider(t.Context(), proj, arn), c.code, c.aws)
		_, err = newEnvOn(t, failingList{Backend: inner, k: iam.KindOIDCProvider, err: c.err}, &now).
			api.ListOpenIDConnectProviders(t.Context(), proj)
		wantAWS(t, err, c.code, c.aws)
		err = newEnvOn(t, failingDelete{Backend: inner, k: iam.KindOIDCProvider, err: c.err}, &now).
			api.DeleteOpenIDConnectProvider(t.Context(), proj, arn)
		wantAWS(t, err, c.code, c.aws)
	}
	_, err := newEnvOn(t, inner, &now).api.ListOpenIDConnectProviders(t.Context(), "Bad_Project")
	wantAWS(t, err, codes.InvalidArgument, "ValidationError")
	storedOIDC(t, inner, iam.OIDCProviderKey(url))
}
