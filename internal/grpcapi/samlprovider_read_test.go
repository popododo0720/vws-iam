package grpcapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/store/storetest"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

func samlARN(pid, name string) string { return "arn:vws:iam::" + pid + ":saml-provider/" + name }

// plainSAMLDoc is valid metadata without a validUntil.
func plainSAMLDoc(note string) string { return storetest.SAMLMetadata(note + strings.Repeat(" ", 100)) }

func samlGone(t *testing.T, b store.Backend, name string) {
	t.Helper()
	_, err := store.Get[iam.SAMLProvider](t.Context(), store.Scoped(b, proj), name)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("provider %q: %v, want deleted", name, err)
	}
}

// seedSAML creates provider corp of the test project, without validUntil.
func seedSAML(t *testing.T, b store.Backend, now *time.Time) {
	t.Helper()
	if _, err := newEnvOn(t, b, now).api.CreateSAMLProvider(t.Context(), proj, "corp", plainSAMLDoc(""), nil); err != nil {
		t.Fatal(err)
	}
}

// TestGetSAMLProvider: a provider created on one replica is returned by
// another started later (a restart reads the same store) with its
// document verbatim, creation time, tags, ARN and the validUntil its
// document sets, zero when it sets none. An ARN whose name differs only in
// case, a provider of another project and an unknown name are
// NoSuchEntity. On both store backends.
func TestGetSAMLProvider(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 4, 0, 0, 0, time.UTC)
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			until := now.Add(48 * time.Hour)
			doc := idp.Metadata(until)
			writer := newEnvOn(t, b, &now)
			if _, err := writer.api.CreateSAMLProvider(t.Context(), proj, "Corp.IdP", doc,
				[]*iamv1.Tag{samlTag("team", "a")}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.api.CreateSAMLProvider(t.Context(), proj, "plain", plainSAMLDoc(""), nil); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.api.CreateSAMLProvider(t.Context(), "beta", "other", plainSAMLDoc(""), nil); err != nil {
				t.Fatal(err)
			}
			restarted := newEnvOn(t, b, &now)
			got, err := restarted.api.GetSAMLProvider(t.Context(), proj, samlARN(proj, "Corp.IdP"))
			if err != nil {
				t.Fatal(err)
			}
			p := got.Provider
			if p.Name != "Corp.IdP" || p.MetadataDocument != doc || !p.Created.Equal(now) ||
				len(p.Tags) != 1 || p.Tags["team"] != "a" || !got.ValidUntil.Equal(until) ||
				got.ARN != samlARN(proj, "Corp.IdP") {
				t.Fatalf("GetSAMLProvider = %s %s until %v tags %v, want Corp.IdP with its document until %v",
					got.ARN, p.Name, got.ValidUntil, p.Tags, until)
			}
			plain, err := restarted.api.GetSAMLProvider(t.Context(), proj, samlARN(proj, "plain"))
			if err != nil || !plain.ValidUntil.IsZero() {
				t.Fatalf("provider without validUntil: %v until %v, want zero", err, plain.ValidUntil)
			}
			for _, arn := range []string{
				samlARN(proj, "corp.idp"), samlARN(proj, "CORP.IDP"), samlARN(proj, "unknown"),
				samlARN(proj, "other"), samlARN("beta", "other"), samlARN("beta", "Corp.IdP"),
			} {
				_, err := restarted.api.GetSAMLProvider(t.Context(), proj, arn)
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
		})
	}
}

// TestListSAMLProviders: the providers of the project only, ordered by
// case-folded name whatever order they were created in, each with its
// ARN, creation time and validUntil; no provider is an empty list. On both
// store backends.
func TestListSAMLProviders(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 3, 4, 0, 0, 0, time.UTC)
			e := newEnvOn(t, b, &now)
			if got, err := e.api.ListSAMLProviders(t.Context(), proj); err != nil || len(got) != 0 {
				t.Fatalf("no provider: %v %v, want an empty list", got, err)
			}
			idp, err := samltest.New(samlIssuer, now)
			if err != nil {
				t.Fatal(err)
			}
			until := now.Add(time.Hour)
			for i, name := range []string{"zeta", "Beta", "alpha"} {
				doc := plainSAMLDoc(name)
				if name == "Beta" {
					doc = idp.Metadata(until)
				}
				now = now.Add(time.Duration(i) * time.Minute)
				if _, err := e.api.CreateSAMLProvider(t.Context(), proj, name, doc, nil); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.api.CreateSAMLProvider(t.Context(), "beta", "aaa", plainSAMLDoc(""), nil); err != nil {
				t.Fatal(err)
			}
			got, err := newEnvOn(t, b, &now).api.ListSAMLProviders(t.Context(), proj)
			if err != nil {
				t.Fatal(err)
			}
			base := time.Date(2026, 11, 3, 4, 0, 0, 0, time.UTC)
			want := []struct {
				name    string
				created time.Time
				until   time.Time
			}{
				{"alpha", base.Add(3 * time.Minute), time.Time{}},
				{"Beta", base.Add(time.Minute), until},
				{"zeta", base, time.Time{}},
			}
			if len(got) != len(want) {
				t.Fatalf("ListSAMLProviders = %+v, want %d providers", got, len(want))
			}
			for i, w := range want {
				g := got[i]
				if g.ARN != samlARN(proj, w.name) || !g.Created.Equal(w.created) || !g.ValidUntil.Equal(w.until) {
					t.Fatalf("entry %d = %+v, want %s created %v until %v", i, g, w.name, w.created, w.until)
				}
			}
		})
	}
}

// TestDeleteSAMLProvider: a provider deleted on one replica is gone on
// every replica: Get is NoSuchEntity, List leaves it out and
// AssumeRoleWithSAML with it is InvalidIdentityToken at once. A repeat is
// NoSuchEntity, as in AWS, an ARN differing only in case deletes nothing,
// another project's provider of the same name stays, and the name can be
// created again. On both store backends.
func TestDeleteSAMLProvider(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			f := newSAMLFixture(t, bk.open())
			writer, reader := f.server(t), f.server(t)
			f.create(t, writer, proj)
			f.create(t, writer, "beta")
			if _, err := reader.api.AssumeSAMLRole(t.Context(), f.signed(t, f.idp)); err != nil {
				t.Fatalf("before the delete: %v", err)
			}
			err := writer.api.DeleteSAMLProvider(t.Context(), proj, samlARN(proj, "CORP"))
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			storedSAML(t, f.b, "corp")

			if err := writer.api.DeleteSAMLProvider(t.Context(), proj, samlIdpARN); err != nil {
				t.Fatal(err)
			}
			samlGone(t, f.b, "corp")
			_, err = reader.api.AssumeSAMLRole(t.Context(), f.signed(t, f.idp))
			wantAWS(t, err, codes.InvalidArgument, "InvalidIdentityToken")
			_, err = reader.api.GetSAMLProvider(t.Context(), proj, samlIdpARN)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			if got, err := reader.api.ListSAMLProviders(t.Context(), proj); err != nil || len(got) != 0 {
				t.Fatalf("list after delete: %+v %v, want empty", got, err)
			}
			err = reader.api.DeleteSAMLProvider(t.Context(), proj, samlIdpARN)
			wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			if _, err := reader.api.GetSAMLProvider(t.Context(), "beta", samlARN("beta", "corp")); err != nil {
				t.Fatalf("another project's provider: %v", err)
			}

			f.create(t, reader, proj)
			if _, err := writer.api.AssumeSAMLRole(t.Context(), f.signed(t, f.idp)); err != nil {
				t.Fatalf("created again: %v", err)
			}
		})
	}
}

// TestDeleteSAMLProviderConcurrent: of deletes of one provider racing on
// two replicas exactly one succeeds and the rest are NoSuchEntity. On both
// store backends.
func TestDeleteSAMLProviderConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			if _, err := replicas[0].api.CreateSAMLProvider(t.Context(), proj, "corp", plainSAMLDoc(""), nil); err != nil {
				t.Fatal(err)
			}
			errs := make([]error, 16)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() { errs[i] = replicas[i%2].api.DeleteSAMLProvider(t.Context(), proj, samlIdpARN) })
			}
			wg.Wait()
			deleted := 0
			for _, err := range errs {
				if err == nil {
					deleted++
					continue
				}
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
			if deleted != 1 {
				t.Fatalf("%d deletes succeeded, want exactly one", deleted)
			}
			samlGone(t, b, "corp")
		})
	}
}

// changingSAMLBeforeDelete rewrites the provider before the first n
// deletes of a SAML provider, as a concurrent write between the read and
// the delete would.
type changingSAMLBeforeDelete struct {
	store.Backend
	mu sync.Mutex
	n  int
	t  *testing.T
}

func (c *changingSAMLBeforeDelete) Delete(ctx context.Context, k iam.Kind, key, version string) error {
	if k == iam.KindSAMLProvider {
		c.mu.Lock()
		change := c.n > 0
		c.n--
		c.mu.Unlock()
		if change {
			b, name := store.Scoped(c.Backend, proj), strings.TrimPrefix(key, proj+"/")
			if _, err := store.Mutate(ctx, b, name, func(p *iam.SAMLProvider) error {
				p.Created = p.Created.Add(time.Second)
				return nil
			}); err != nil {
				c.t.Error(err)
			}
		}
	}
	return c.Backend.Delete(ctx, k, key, version)
}

// TestDeleteSAMLProviderStaleRead: a provider written after it was read is
// read again and then deleted, never deleted blind at a stale version;
// one that keeps changing is ConcurrentModification and stays. On both
// store backends.
func TestDeleteSAMLProviderStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seed := newEnvOn(t, inner, &now)
			for _, name := range []string{"corp", "busy"} {
				if _, err := seed.api.CreateSAMLProvider(t.Context(), proj, name, plainSAMLDoc(""), nil); err != nil {
					t.Fatal(err)
				}
			}
			b := &changingSAMLBeforeDelete{Backend: inner, n: 1, t: t}
			if err := newEnvOn(t, b, &now).api.DeleteSAMLProvider(t.Context(), proj, samlIdpARN); err != nil {
				t.Fatalf("delete after one concurrent write: %v, want deleted", err)
			}
			samlGone(t, inner, "corp")

			b = &changingSAMLBeforeDelete{Backend: inner, n: 1 << 30, t: t}
			err := newEnvOn(t, b, &now).api.DeleteSAMLProvider(t.Context(), proj, samlARN(proj, "busy"))
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			storedSAML(t, inner, "busy")
		})
	}
}

// TestDeleteSAMLProviderCanceled: a canceled delete deletes nothing, and
// the same request afterwards deletes the provider.
func TestDeleteSAMLProviderCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	if _, err := e.api.CreateSAMLProvider(t.Context(), proj, "corp", plainSAMLDoc(""), nil); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := e.api.DeleteSAMLProvider(canceled, proj, samlIdpARN); err == nil {
		t.Fatal("a canceled delete succeeded")
	}
	storedSAML(t, b, "corp")
	if err := e.api.DeleteSAMLProvider(t.Context(), proj, samlIdpARN); err != nil {
		t.Fatalf("the same request afterwards: %v", err)
	}
	samlGone(t, b, "corp")
}

// TestSAMLProviderARNErrors: Get and Delete answer a bad project or an ARN
// outside 20 to 2048 characters with ValidationError and an ARN that is
// not a SAML provider ARN with InvalidInput, before any store access (the
// store here fails every read), and an ARN of another account with
// NoSuchEntity; the AWS length bounds are accepted. Nothing is deleted.
func TestSAMLProviderARNErrors(t *testing.T) {
	inner := memstore.New()
	now := time.Now().UTC()
	seedSAML(t, inner, &now)
	down := newEnvOn(t, failingGet{Backend: inner, k: iam.KindSAMLProvider, err: store.ErrUnavailable}, &now)
	up := newEnvOn(t, inner, &now)
	long := samlARN(proj, strings.Repeat("a", 128))
	cases := []struct {
		name, pid, arn string
		code           codes.Code
		aws            string
		e              *env
	}{
		{"bad project", "Bad Project", samlIdpARN, codes.InvalidArgument, "ValidationError", down},
		{"19 characters", proj, strings.Repeat("a", 19), codes.InvalidArgument, "ValidationError", down},
		{"2049 characters", proj, long + strings.Repeat("a", 2049-len(long)), codes.InvalidArgument, "ValidationError", down},
		{"empty", proj, "", codes.InvalidArgument, "ValidationError", down},
		{"role ARN", proj, samlRoleARN, codes.InvalidArgument, "InvalidInput", down},
		{"other partition", proj, "arn:aws" + samlIdpARN[len("arn:vws"):], codes.InvalidArgument, "InvalidInput", down},
		{"no account", proj, "arn:vws:iam:::saml-provider/corp", codes.InvalidArgument, "InvalidInput", down},
		{"colon in account", proj, "arn:vws:iam::a:b:saml-provider/corp", codes.InvalidArgument, "InvalidInput", down},
		{"bad account", proj, "arn:vws:iam::bad account:saml-provider/corp", codes.InvalidArgument, "InvalidInput", down},
		{"bad name", proj, samlARN(proj, "corp/x"), codes.InvalidArgument, "InvalidInput", down},
		{"name of 129", proj, samlARN(proj, strings.Repeat("a", 129)), codes.InvalidArgument, "InvalidInput", down},
		{"no name", proj, samlARN(proj, ""), codes.InvalidArgument, "InvalidInput", down},
		{"another account", proj, samlARN("beta", "corp"), codes.NotFound, "NoSuchEntity", down},
		{"longest name", proj, long, codes.NotFound, "NoSuchEntity", up},
		{"store down", proj, samlIdpARN, codes.Unavailable, "ServiceUnavailable", down},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.e.api.GetSAMLProvider(t.Context(), c.pid, c.arn)
			wantAWS(t, err, c.code, c.aws)
			err = c.e.api.DeleteSAMLProvider(t.Context(), c.pid, c.arn)
			wantAWS(t, err, c.code, c.aws)
			storedSAML(t, inner, "corp")
		})
	}
	_, err := down.api.ListSAMLProviders(t.Context(), "Bad Project")
	wantAWS(t, err, codes.InvalidArgument, "ValidationError")
}

// TestSAMLProviderStoreFailures: a failed list is ServiceUnavailable or
// InternalFailure, and a failed delete is InternalFailure and keeps the
// provider.
func TestSAMLProviderStoreFailures(t *testing.T) {
	inner := memstore.New()
	now := time.Now().UTC()
	seedSAML(t, inner, &now)
	_, err := newEnvOn(t, failingList{Backend: inner, k: iam.KindSAMLProvider, err: store.ErrUnavailable}, &now).
		api.ListSAMLProviders(t.Context(), proj)
	wantAWS(t, err, codes.Unavailable, "ServiceUnavailable")
	_, err = newEnvOn(t, failingList{Backend: inner, k: iam.KindSAMLProvider, err: errors.New("boom")}, &now).
		api.ListSAMLProviders(t.Context(), proj)
	wantAWS(t, err, codes.Internal, "InternalFailure")
	err = newEnvOn(t, failingDelete{Backend: inner, k: iam.KindSAMLProvider, err: errors.New("boom")}, &now).
		api.DeleteSAMLProvider(t.Context(), proj, samlIdpARN)
	wantAWS(t, err, codes.Internal, "InternalFailure")
	storedSAML(t, inner, "corp")
}

// corruptSAMLList lists every SAML provider as a record whose document no
// longer parses.
type corruptSAMLList struct{ store.Backend }

func (c corruptSAMLList) List(ctx context.Context, k iam.Kind) ([]store.Entry, error) {
	if k != iam.KindSAMLProvider {
		return c.Backend.List(ctx, k)
	}
	spec, err := json.Marshal(iam.SAMLProvider{Name: "corp", MetadataDocument: "<md:EntityDescriptor>CANARY"})
	return []store.Entry{{Key: proj + "/corp", Spec: spec, Version: "1"}}, err
}

// TestSAMLProviderCorruptDocument: a stored document that no longer parses
// is InternalFailure in Get and List, and the error never carries it.
func TestSAMLProviderCorruptDocument(t *testing.T) {
	now := time.Now().UTC()
	for name, b := range map[string]store.Backend{
		"get":  corruptSAMLGet{Backend: memstore.New()},
		"list": corruptSAMLList{Backend: memstore.New()},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnvOn(t, b, &now)
			var err error
			if name == "get" {
				_, err = e.api.GetSAMLProvider(t.Context(), proj, samlIdpARN)
			} else {
				_, err = e.api.ListSAMLProviders(t.Context(), proj)
			}
			wantAWS(t, err, codes.Internal, "InternalFailure")
			if strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("error carries the document: %v", err)
			}
		})
	}
}
