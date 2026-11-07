package sts_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/sts"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

// storedSAMLSetup is samlSetup serving the providers stored in the backend
// (WithStoredSAML) instead of injected ones; corp is stored, valid for a
// day.
func storedSAMLSetup(t *testing.T) samlEnv {
	t.Helper()
	e := samlSetup(t)
	put(t, e.b, iam.SAMLProvider{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: "corp", Created: e.clk.now(),
		MetadataDocument: e.idp.Metadata(e.clk.now().Add(24 * time.Hour)),
	})
	e.svc = sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithStoredSAML(samlSP))
	return e
}

// TestAssumeRoleWithSAMLStoredProvider: with WithStoredSAML a response
// signed by the IdP of the stored provider gets role credentials, from a
// service built later on the same store too (a restart or another
// replica); a deleted provider, an ARN that names it in another case and
// an empty service provider are InvalidIdentityToken.
func TestAssumeRoleWithSAMLStoredProvider(t *testing.T) {
	e := storedSAMLSetup(t)
	ctx := context.Background()
	if _, err := e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion))); err != nil {
		t.Fatalf("stored provider: %v", err)
	}
	again := sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithStoredSAML(samlSP))
	if _, err := again.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion))); err != nil {
		t.Fatalf("stored provider after a restart: %v", err)
	}

	upper := "arn:vws:iam::" + acct + ":saml-provider/CORP"
	a := e.claims()
	a.Roles = []string{upper + "," + samlRoleARN}
	req := samlReq(e.response(t, a, samltest.SignAssertion))
	req.PrincipalARN = upper
	if _, err := e.svc.AssumeRoleWithSAML(ctx, req); !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Fatalf("ARN in another case: %v, want InvalidIdentityToken", err)
	}

	unset := sts.New(e.b, e.keys, e.az, acct, e.clk.now, sts.WithStoredSAML(sts.SAMLServiceProvider{}))
	_, err := unset.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
	if !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Fatalf("no service provider: %v, want InvalidIdentityToken", err)
	}

	v, err := store.Get[iam.SAMLProvider](ctx, e.b, "corp")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.b.Delete(ctx, iam.KindSAMLProvider, "corp", v.Version); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.AssumeRoleWithSAML(ctx, samlReq(e.response(t, e.claims(), samltest.SignAssertion)))
	if !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Fatalf("deleted provider: %v, want InvalidIdentityToken", err)
	}
}

// TestAssumeRoleWithSAMLStoredProviderExpired: a stored provider whose
// metadata validUntil has passed is InvalidIdentityToken.
func TestAssumeRoleWithSAMLStoredProviderExpired(t *testing.T) {
	e := storedSAMLSetup(t)
	resp := e.response(t, e.claims(), samltest.SignAssertion)
	e.clk.t = e.clk.t.Add(25 * time.Hour)
	_, err := e.svc.AssumeRoleWithSAML(context.Background(), samlReq(resp))
	if !errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Fatalf("expired metadata: %v, want InvalidIdentityToken", err)
	}
}

// corruptSAML answers every SAML provider read with a record whose
// document no longer parses, as an operator edit of the custom resource
// could leave it.
type corruptSAML struct {
	store.Backend
	spec []byte
}

func (c corruptSAML) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	if kind == iam.KindSAMLProvider {
		return store.Entry{Key: key, Spec: c.spec, Version: "1"}, nil
	}
	return c.Backend.Get(ctx, kind, key)
}

// TestAssumeRoleWithSAMLStoredProviderFaults: a store failure and a stored
// document that no longer parses are errors that issue nothing and are
// not InvalidIdentityToken (the caller did nothing wrong); neither error
// carries the document.
func TestAssumeRoleWithSAMLStoredProviderFaults(t *testing.T) {
	e := storedSAMLSetup(t)
	ctx := context.Background()
	resp := e.response(t, e.claims(), samltest.SignAssertion)

	down := sts.New(downOn{Backend: e.b, kind: iam.KindSAMLProvider}, e.keys, e.az, acct, e.clk.now,
		sts.WithStoredSAML(samlSP))
	if _, err := down.AssumeRoleWithSAML(ctx, samlReq(resp)); !errors.Is(err, store.ErrUnavailable) ||
		errors.Is(err, sts.ErrInvalidIdentityToken) {
		t.Fatalf("store down: %v, want ErrUnavailable", err)
	}

	const canary = "CANARY-DOCUMENT-TEXT"
	spec, err := json.Marshal(iam.SAMLProvider{Name: "corp", MetadataDocument: "<md:EntityDescriptor>" + canary})
	if err != nil {
		t.Fatal(err)
	}
	bad := sts.New(corruptSAML{Backend: e.b, spec: spec}, e.keys, e.az, acct, e.clk.now, sts.WithStoredSAML(samlSP))
	_, err = bad.AssumeRoleWithSAML(ctx, samlReq(resp))
	if !errors.Is(err, iam.ErrSAMLMetadata) || errors.Is(err, sts.ErrInvalidIdentityToken) ||
		errors.Is(err, store.ErrNotFound) {
		t.Fatalf("corrupt stored document: %v, want ErrSAMLMetadata", err)
	}
	if strings.Contains(err.Error(), canary) {
		t.Fatalf("error carries the document: %v", err)
	}
}
