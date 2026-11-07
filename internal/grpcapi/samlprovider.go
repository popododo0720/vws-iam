package grpcapi

import (
	"context"
	"errors"
	"strconv"
	"unicode/utf8"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// samlProviderView is a SAML provider with its ARN.
type samlProviderView struct {
	Provider iam.SAMLProvider
	ARN      string
}

// createSAMLProvider is IAM CreateSAMLProvider: it creates SAML provider
// name in project pid from the IdP metadata document, with tags, and
// returns it with its ARN.
//
// A bad project id, a Name outside 1 to 128 characters of [\w._-], a
// SAMLMetadataDocument outside 1000 to 10,000,000 characters, or more
// than 50 tags in the request is ValidationError before any store access.
// A tag outside the AWS tag rules is InvalidInput, and of a key repeated
// in the request the last value is kept (as TagPolicy). A document that
// is not usable IdP metadata (iam.ParseSAMLMetadata: one EntityDescriptor
// with an entityID and an IDPSSODescriptor with at least one signing
// certificate, no DTD) is InvalidInput with a fixed description that never
// carries the document. VWS stores a provider as one custom resource, so
// a provider whose stored encoding passes iam.MaxSAMLProviderEncodedLen
// bytes is InvalidInput too: a documented limit below the AWS 10,000,000
// characters. A name that is taken, in any case, is EntityAlreadyExists
// and the stored provider stays: the create is one store create, so of
// racing requests on any replica exactly one makes the provider, and a
// retry after a lost response is EntityAlreadyExists, as in AWS. A request
// that was canceled or whose deadline passed writes nothing. A store
// failure is InternalFailure. The SAMLProvidersPerAccount quota is not
// enforced yet. Authorization (iam:CreateSAMLProvider) is console-api's.
//
// TODO(#196): serve this as an RPC once vws-proto carries CreateSAMLProvider.
func (s *Server) createSAMLProvider(
	ctx context.Context, pid, name, document string, tags []*iamv1.Tag,
) (samlProviderView, error) {
	if !iam.ValidProject(pid) {
		return samlProviderView{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if !iam.ValidSAMLProviderName(name) {
		return samlProviderView{}, invalidSpec("name must be 1 to " + strconv.Itoa(iam.MaxSAMLProviderNameLen) +
			" characters of [\\w._-]")
	}
	if n := utf8.RuneCountInString(document); n < iam.MinSAMLMetadataLen || n > iam.MaxSAMLMetadataLen {
		return samlProviderView{}, invalidSpec("samlMetadataDocument must be " + strconv.Itoa(iam.MinSAMLMetadataLen) +
			" to " + strconv.Itoa(iam.MaxSAMLMetadataLen) + " characters")
	}
	if len(tags) > iam.MaxSAMLProviderTags {
		return samlProviderView{}, invalidSpec("tags must have at most " + strconv.Itoa(iam.MaxSAMLProviderTags) + " items")
	}
	var kept map[string]string
	if len(tags) > 0 {
		kept = make(map[string]string, len(tags))
	}
	for _, tag := range tags {
		if err := iam.CheckTag(tag.GetKey(), tag.GetValue()); err != nil {
			return samlProviderView{}, invalidInput(err.Error())
		}
		kept[tag.GetKey()] = tag.GetValue()
	}
	sp := iam.SAMLProvider{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, Name: name, Created: s.now().UTC(),
		MetadataDocument: document, Tags: kept,
	}
	if err := sp.Validate(); err != nil {
		switch {
		case errors.Is(err, iam.ErrSAMLProviderTooLarge):
			return samlProviderView{}, invalidInput("this service stores a SAML provider in at most " +
				strconv.Itoa(iam.MaxSAMLProviderEncodedLen) + " encoded bytes")
		case errors.Is(err, iam.ErrSAMLMetadata):
			_, why := iam.ParseSAMLMetadata(document) // fixed text, never the document
			return samlProviderView{}, invalidInput("the SAML metadata document is not usable: " + why.Error())
		}
		return samlProviderView{}, invalidSpec(err.Error())
	}
	if err := ctx.Err(); err != nil {
		return samlProviderView{}, toStatus(ctx, err) // the caller is gone; write nothing
	}
	p := s.project(pid)
	_, err := store.Create(ctx, p.b, sp)
	if errors.Is(err, store.ErrExists) {
		return samlProviderView{}, alreadyExists("Provider with name " + name + " already exists.")
	}
	if err != nil {
		return samlProviderView{}, toStatus(ctx, err)
	}
	return samlProviderView{Provider: sp, ARN: iam.SAMLProviderARN(p.id, sp)}, nil
}
