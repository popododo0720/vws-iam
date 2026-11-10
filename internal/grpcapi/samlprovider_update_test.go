package grpcapi_test

import (
	"context"
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
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

// TestUpdateSAMLProvider: a document replaced on one replica serves
// AssumeRoleWithSAML on another at once: a response signed by the new
// IdP gets credentials and one signed by the old IdP is
// InvalidIdentityToken. The name, tags, creation time and UID stay and the
// generation moves; a replica started later reads the new document. A
// repeat writes nothing, and an ARN differing only in case, an unknown
// provider and another project's provider are NoSuchEntity and change
// nothing. On both store backends.
func TestUpdateSAMLProvider(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			f := newSAMLFixture(t, bk.open())
			writer, reader := f.server(t), f.server(t)
			created := f.now
			if _, err := writer.api.CreateSAMLProvider(t.Context(), proj, "corp", f.idp.Metadata(f.now.Add(time.Hour)),
				[]*iamv1.Tag{samlTag("team", "a")}); err != nil {
				t.Fatal(err)
			}
			f.create(t, writer, "beta")
			before := storedSAML(t, f.b, "corp")
			if _, err := reader.api.AssumeSAMLRole(t.Context(), f.signed(t, f.idp)); err != nil {
				t.Fatalf("before the update: %v", err)
			}

			rotated, err := samltest.New(samlIssuer, f.now)
			if err != nil {
				t.Fatal(err)
			}
			until := f.now.Add(2 * time.Hour).Truncate(time.Second)
			doc := rotated.Metadata(until)
			f.now = f.now.Add(time.Minute)
			arn, err := writer.api.UpdateSAMLProvider(t.Context(), proj, samlIdpARN, doc)
			if err != nil || arn != samlIdpARN {
				t.Fatalf("UpdateSAMLProvider = %q, %v, want %s", arn, err, samlIdpARN)
			}
			if _, err := reader.api.AssumeSAMLRole(t.Context(), f.signed(t, rotated)); err != nil {
				t.Fatalf("signed by the new IdP: %v", err)
			}
			_, err = reader.api.AssumeSAMLRole(t.Context(), f.signed(t, f.idp))
			wantAWS(t, err, codes.InvalidArgument, "InvalidIdentityToken")

			after := storedSAML(t, f.b, "corp")
			p := after.Object
			if p.MetadataDocument != doc || p.Name != "corp" || p.UID != before.Object.UID ||
				!p.Created.Equal(created) || len(p.Tags) != 1 || p.Tags["team"] != "a" ||
				p.Generation != before.Object.Generation+1 || !p.Updated.Equal(f.now) {
				t.Fatalf("stored after update: %+v, want the new document with name, UID, tags and creation kept", p.Meta)
			}
			got, err := f.server(t).api.GetSAMLProvider(t.Context(), proj, samlIdpARN)
			if err != nil || got.Provider.MetadataDocument != doc || !got.ValidUntil.Equal(until) {
				t.Fatalf("a replica started later: %v until %v, want the new document until %v", err, got.ValidUntil, until)
			}

			if arn, err := reader.api.UpdateSAMLProvider(t.Context(), proj, samlIdpARN, doc); err != nil || arn != samlIdpARN {
				t.Fatalf("repeat: %q, %v", arn, err)
			}
			if v := storedSAML(t, f.b, "corp").Version; v != after.Version {
				t.Fatalf("a repeat wrote the provider: version %s, want %s", v, after.Version)
			}

			other := plainSAMLDoc("other")
			for _, a := range []string{samlARN(proj, "CORP"), samlARN(proj, "unknown"), samlARN("beta", "corp")} {
				_, err := writer.api.UpdateSAMLProvider(t.Context(), proj, a, other)
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
			if storedSAML(t, f.b, "corp").Version != after.Version {
				t.Fatal("an update of another ARN wrote corp")
			}
			if got, err := reader.api.GetSAMLProvider(t.Context(), "beta", samlARN("beta", "corp")); err != nil ||
				got.Provider.MetadataDocument == doc {
				t.Fatalf("another project's provider: %v, want it unchanged", err)
			}
		})
	}
}

// TestUpdateSAMLProviderConcurrent: updates of one provider to one
// document racing on two replicas all succeed and write it once. On both
// store backends.
func TestUpdateSAMLProviderConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			seedSAML(t, b, &now)
			doc := plainSAMLDoc("new")
			errs := make([]error, 8)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					_, errs[i] = replicas[i%2].api.UpdateSAMLProvider(t.Context(), proj, samlIdpARN, doc)
				})
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("update %d: %v", i, err)
				}
			}
			p := storedSAML(t, b, "corp").Object
			if p.MetadataDocument != doc || p.Generation != 2 {
				t.Fatalf("generation %d, want the document written once (2)", p.Generation)
			}
		})
	}
}

// changingSAMLBeforeUpdate rewrites the provider before the first n
// updates of a SAML provider, as a concurrent write between the read and
// the update would.
type changingSAMLBeforeUpdate struct {
	store.Backend
	mu sync.Mutex
	n  int
	t  *testing.T
}

func (c *changingSAMLBeforeUpdate) Update(
	ctx context.Context, k iam.Kind, key string, spec []byte, version string,
) (string, error) {
	if k == iam.KindSAMLProvider {
		c.mu.Lock()
		change := c.n > 0
		c.n--
		c.mu.Unlock()
		if change {
			b, name := store.Scoped(c.Backend, proj), strings.TrimPrefix(key, proj+"/")
			cur, err := store.Get[iam.SAMLProvider](ctx, b, name)
			if err != nil {
				c.t.Error(err)
				return "", err
			}
			p := cur.Object
			p.Tags = map[string]string{"writer": "other"}
			if _, err := store.Update(ctx, b, p, cur.Version); err != nil {
				c.t.Error(err)
			}
		}
	}
	return c.Backend.Update(ctx, k, key, spec, version)
}

// TestUpdateSAMLProviderStaleRead: a provider written after it was read is
// read again and then updated, keeping the other writer's change, never
// written from a stale copy; one that keeps changing is
// ConcurrentModification and keeps its document. On both store backends.
func TestUpdateSAMLProviderStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedSAML(t, inner, &now)
			doc := plainSAMLDoc("new")
			b := &changingSAMLBeforeUpdate{Backend: inner, n: 1, t: t}
			if _, err := newEnvOn(t, b, &now).api.UpdateSAMLProvider(t.Context(), proj, samlIdpARN, doc); err != nil {
				t.Fatalf("update after one concurrent write: %v", err)
			}
			p := storedSAML(t, inner, "corp").Object
			if p.MetadataDocument != doc || p.Tags["writer"] != "other" {
				t.Fatalf("stored %v, want the new document and the other writer's tags", p.Tags)
			}

			b = &changingSAMLBeforeUpdate{Backend: inner, n: 1 << 30, t: t}
			_, err := newEnvOn(t, b, &now).api.UpdateSAMLProvider(t.Context(), proj, samlIdpARN, plainSAMLDoc("lost"))
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			if storedSAML(t, inner, "corp").Object.MetadataDocument != doc {
				t.Fatal("a ConcurrentModification update changed the document")
			}
		})
	}
}

// TestUpdateSAMLProviderCanceled: a canceled update writes nothing, and
// the same request afterwards updates the provider.
func TestUpdateSAMLProviderCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	seedSAML(t, b, &now)
	e := newEnvOn(t, b, &now)
	doc := plainSAMLDoc("new")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.api.UpdateSAMLProvider(canceled, proj, samlIdpARN, doc); err == nil {
		t.Fatal("a canceled update succeeded")
	}
	if storedSAML(t, b, "corp").Object.MetadataDocument == doc {
		t.Fatal("a canceled update wrote the document")
	}
	if _, err := e.api.UpdateSAMLProvider(t.Context(), proj, samlIdpARN, doc); err != nil {
		t.Fatalf("the same request afterwards: %v", err)
	}
	if storedSAML(t, b, "corp").Object.MetadataDocument != doc {
		t.Fatal("the update did not write the document")
	}
}

// TestUpdateSAMLProviderErrors: a bad project, a bad ARN, a document
// outside 1000 to 10,000,000 characters (none included) and a document
// that is not IdP metadata are answered before any store access (the
// store here fails every read), without the document in the error; a
// provider too large to store is InvalidInput and a store failure
// InternalFailure or ServiceUnavailable. None changes the stored provider.
func TestUpdateSAMLProviderErrors(t *testing.T) {
	inner := memstore.New()
	now := time.Now().UTC()
	seedSAML(t, inner, &now)
	stored := storedSAML(t, inner, "corp")
	down := newEnvOn(t, failingGet{Backend: inner, k: iam.KindSAMLProvider, err: store.ErrUnavailable}, &now)
	up := newEnvOn(t, inner, &now)
	boom := errors.New("backend down")
	good := plainSAMLDoc("new")
	notMetadata := "<root>CANARY" + strings.Repeat("x", 1000) + "</root>"
	// <, > and & are six bytes each once encoded, so this document fits
	// the AWS character limit but not one custom resource.
	huge := plainSAMLDoc(strings.Repeat("<&>", iam.MaxSAMLProviderEncodedLen/12))
	cases := []struct {
		name, pid, arn, doc string
		code                codes.Code
		aws                 string
		e                   *env
	}{
		{"bad project", "Bad Project", samlIdpARN, good, codes.InvalidArgument, "ValidationError", down},
		{"short ARN", proj, strings.Repeat("a", 19), good, codes.InvalidArgument, "ValidationError", down},
		{"role ARN", proj, samlRoleARN, good, codes.InvalidArgument, "InvalidInput", down},
		{"no document", proj, samlIdpARN, "", codes.InvalidArgument, "ValidationError", down},
		{"999 characters", proj, samlIdpARN, strings.Repeat("x", 999), codes.InvalidArgument, "ValidationError", down},
		{
			"over 10,000,000", proj, samlIdpARN, strings.Repeat("x", iam.MaxSAMLMetadataLen+1),
			codes.InvalidArgument, "ValidationError", down,
		},
		{"not metadata", proj, samlIdpARN, notMetadata, codes.InvalidArgument, "InvalidInput", down},
		{"another account", proj, samlARN("beta", "corp"), good, codes.NotFound, "NoSuchEntity", down},
		{"store down", proj, samlIdpARN, good, codes.Unavailable, "ServiceUnavailable", down},
		{"too large to store", proj, samlIdpARN, huge, codes.InvalidArgument, "InvalidInput", up},
		{
			"read fails", proj, samlIdpARN, good, codes.Internal, "InternalFailure",
			newEnvOn(t, failingGet{Backend: inner, k: iam.KindSAMLProvider, err: boom}, &now),
		},
		{
			"write fails", proj, samlIdpARN, good, codes.Internal, "InternalFailure",
			newEnvOn(t, failingUpdate{Backend: inner, k: iam.KindSAMLProvider, err: boom}, &now),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.e.api.UpdateSAMLProvider(t.Context(), c.pid, c.arn, c.doc)
			wantAWS(t, err, c.code, c.aws)
			if strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("error carries the document: %v", err)
			}
			if v := storedSAML(t, inner, "corp").Version; v != stored.Version {
				t.Fatalf("stored provider written: version %s, want %s", v, stored.Version)
			}
		})
	}
}
