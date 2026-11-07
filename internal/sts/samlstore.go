package sts

import (
	"context"
	"fmt"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// WithStoredSAML serves AssumeRoleWithSAML from the SAML providers stored
// in the service's backend (CreateSAMLProvider, #196), with sp as this
// service provider. The stored metadata document is parsed on every call,
// so a provider changed or deleted on any replica applies at once. With
// either value of sp empty, AssumeRoleWithSAML refuses every call with
// InvalidIdentityToken, as without the option.
func WithStoredSAML(sp SAMLServiceProvider) Option {
	return func(s *Service) { s.saml, s.samlSP = storedSAMLProviders{s: s}, sp }
}

// storedSAMLProviders reads SAML providers of s's account from s's backend.
type storedSAMLProviders struct{ s *Service }

// SAMLProvider returns the stored provider arn names. The store finds a
// name in any case; the returned ARN carries the name as stored, so
// AssumeRoleWithSAML refuses an ARN that differs from it only in case. An
// ARN of another account or kind, an unknown name and a pending provider
// (one whose create has not committed) are store.ErrNotFound.
// A stored document that no longer parses is an error that is not
// ErrNotFound (an operator fault, never a client one), and carries no
// document text.
func (p storedSAMLProviders) SAMLProvider(ctx context.Context, arn string) (SAMLProvider, error) {
	name, ok := p.s.samlProviderName(arn)
	if !ok {
		return SAMLProvider{}, store.ErrNotFound
	}
	v, err := store.Get[iam.SAMLProvider](ctx, p.s.b, name)
	if err != nil {
		return SAMLProvider{}, fmt.Errorf("get SAML provider %q: %w", name, err)
	}
	if v.Object.Pending {
		return SAMLProvider{}, store.ErrNotFound
	}
	md, err := iam.ParseSAMLMetadata(v.Object.MetadataDocument)
	if err != nil {
		return SAMLProvider{}, fmt.Errorf("stored SAML provider %q: %w", name, err)
	}
	return SAMLProvider{
		ARN:          iam.SAMLProviderARN(p.s.account, v.Object),
		EntityID:     md.EntityID,
		Certificates: md.Certificates,
		ValidUntil:   md.ValidUntil,
	}, nil
}
