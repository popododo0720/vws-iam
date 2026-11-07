package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// samlProviderView is a SAML provider with its ARN and the validUntil of
// its metadata document (zero when the document sets none).
type samlProviderView struct {
	Provider   iam.SAMLProvider
	ARN        string
	ValidUntil time.Time
}

// samlProviderEntry is one provider of ListSAMLProviders, in the AWS
// SAMLProviderListEntry shape.
type samlProviderEntry struct {
	ARN        string
	ValidUntil time.Time
	Created    time.Time
}

// SAML provider ARN bounds of the AWS SAMLProviderArn parameter.
const (
	minSAMLProviderARNLen = 20
	maxSAMLProviderARNLen = 2048
)

// viewSAMLProvider is the view of stored provider sp of account. A stored
// document that no longer parses (an operator edit of the custom resource;
// every write validates it) is an error that maps to InternalFailure and
// names the provider and the fixed fault, never document content.
func viewSAMLProvider(account string, sp iam.SAMLProvider) (samlProviderView, error) {
	md, err := iam.ParseSAMLMetadata(sp.MetadataDocument)
	if err != nil {
		return samlProviderView{}, fmt.Errorf("stored SAML provider %q: %w", sp.Name, err)
	}
	return samlProviderView{Provider: sp, ARN: iam.SAMLProviderARN(account, sp), ValidUntil: md.ValidUntil}, nil
}

// samlProviderName returns the provider name a SAMLProviderArn of project
// pid names. An ARN outside 20 to 2048 characters is ValidationError; one
// that is not a SAML provider ARN is InvalidInput; one of another account
// is NoSuchEntity (missing), as a provider of another project is not
// visible here.
func samlProviderName(pid, arn string, missing error) (string, error) {
	if n := utf8.RuneCountInString(arn); n < minSAMLProviderARNLen || n > maxSAMLProviderARNLen {
		return "", invalidSpec("samlProviderArn must be " + strconv.Itoa(minSAMLProviderARNLen) + " to " +
			strconv.Itoa(maxSAMLProviderARNLen) + " characters")
	}
	rest, ok := strings.CutPrefix(arn, "arn:"+iam.Partition+":iam::")
	account, name, cut := strings.Cut(rest, ":saml-provider/")
	if !ok || !cut || account == "" || strings.Contains(account, ":") || !iam.ValidSAMLProviderName(name) {
		return "", invalidInput("samlProviderArn " + quote(arn) + " is not a SAML provider ARN")
	}
	if account != pid {
		return "", missing
	}
	return name, nil
}

// readSAMLProvider reads the provider arn names in project p. The store
// finds a name in any case, but the ARN must carry the name as stored, as
// AssumeRoleWithSAML requires (sts.WithStoredSAML): an ARN differing only
// in case is NoSuchEntity (missing).
func readSAMLProvider(
	ctx context.Context, p project, name string, missing error,
) (store.Versioned[iam.SAMLProvider], error) {
	cur, err := store.Get[iam.SAMLProvider](ctx, p.b, name)
	if errors.Is(err, store.ErrNotFound) || (err == nil && cur.Object.Name != name) {
		return store.Versioned[iam.SAMLProvider]{}, missing
	}
	if err != nil {
		return store.Versioned[iam.SAMLProvider]{}, toStatus(ctx, err)
	}
	return cur, nil
}

func noSAMLProvider(arn string) error {
	return notFound("SAML provider " + arn + " cannot be found.")
}

// getSAMLProvider is IAM GetSAMLProvider: the SAML provider arn names in
// project pid, with its metadata document as stored, creation time, tags
// and the validUntil its document sets.
//
// A bad project id or an ARN outside 20 to 2048 characters is
// ValidationError and an ARN that is not a SAML provider ARN InvalidInput,
// both before any store access. An ARN of another account, an unknown
// provider and an ARN whose name differs from the stored one only in case
// are NoSuchEntity. A stored document that no longer parses is
// InternalFailure without the document; a store failure is InternalFailure
// (ServiceUnavailable when the store is unavailable). The call only reads.
// The assertion encryption fields of the AWS response are not modeled.
// Authorization (iam:GetSAMLProvider) is console-api's.
//
// TODO(#196): serve this as an RPC once vws-proto carries GetSAMLProvider.
func (s *Server) getSAMLProvider(ctx context.Context, pid, arn string) (samlProviderView, error) {
	if !iam.ValidProject(pid) {
		return samlProviderView{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	missing := noSAMLProvider(arn)
	name, err := samlProviderName(pid, arn, missing)
	if err != nil {
		return samlProviderView{}, err
	}
	p := s.project(pid)
	cur, err := readSAMLProvider(ctx, p, name, missing)
	if err != nil {
		return samlProviderView{}, err
	}
	v, err := viewSAMLProvider(p.id, cur.Object)
	if err != nil {
		return samlProviderView{}, toStatus(ctx, err)
	}
	return v, nil
}

// listSAMLProviders is IAM ListSAMLProviders: every SAML provider of
// project pid with its ARN, validUntil and creation time, ordered by
// case-folded name. AWS pages nothing here, so neither does this.
//
// A bad project id is ValidationError before any store access. No
// provider is an empty list. A stored document that no longer parses, or a
// store failure, is InternalFailure (ServiceUnavailable when the store is
// unavailable) without document content. The call only reads.
// Authorization (iam:ListSAMLProviders) is console-api's.
//
// TODO(#196): serve this as an RPC once vws-proto carries ListSAMLProviders.
func (s *Server) listSAMLProviders(ctx context.Context, pid string) ([]samlProviderEntry, error) {
	if !iam.ValidProject(pid) {
		return nil, invalidID("project " + quote(pid) + " is not a project id")
	}
	p := s.project(pid)
	all, err := store.List[iam.SAMLProvider](ctx, p.b)
	if err != nil {
		return nil, toStatus(ctx, err)
	}
	slices.SortFunc(all, func(a, b store.Versioned[iam.SAMLProvider]) int {
		return strings.Compare(store.Fold(a.Object.Name), store.Fold(b.Object.Name))
	})
	out := make([]samlProviderEntry, 0, len(all))
	for _, cur := range all {
		v, err := viewSAMLProvider(p.id, cur.Object)
		if err != nil {
			return nil, toStatus(ctx, err)
		}
		out = append(out, samlProviderEntry{ARN: v.ARN, ValidUntil: v.ValidUntil, Created: v.Provider.Created})
	}
	return out, nil
}

// deleteSAMLProvider is IAM DeleteSAMLProvider: it deletes the SAML
// provider arn names in project pid. AssumeRoleWithSAML reads the stored
// provider on every call, so it refuses the provider on every replica at
// once; roles that trust it are left as they are, as in AWS.
//
// The argument errors are those of getSAMLProvider, before any store
// access. An unknown provider is NoSuchEntity, so a retry after a lost
// response is NoSuchEntity, as in AWS, and of racing deletes on any
// replica exactly one succeeds. The delete is conditional on the version
// read: a provider written in between is read again, up to
// maxDeleteAttempts, then ConcurrentModification and it stays. A request
// that was canceled or whose deadline passed deletes nothing. A store
// failure is InternalFailure. Authorization (iam:DeleteSAMLProvider) is
// console-api's.
//
// TODO(#196): serve this as an RPC once vws-proto carries DeleteSAMLProvider.
func (s *Server) deleteSAMLProvider(ctx context.Context, pid, arn string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	missing := noSAMLProvider(arn)
	name, err := samlProviderName(pid, arn, missing)
	if err != nil {
		return err
	}
	p := s.project(pid)
	for attempt := 1; ; attempt++ {
		cur, err := readSAMLProvider(ctx, p, name, missing)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return toStatus(ctx, err) // the caller is gone; delete nothing
		}
		err = store.Delete[iam.SAMLProvider](ctx, p.b, name, cur.Version)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, store.ErrConflict) && attempt < maxDeleteAttempts:
			continue
		case errors.Is(err, store.ErrNotFound):
			return missing
		default:
			return toStatus(ctx, err)
		}
	}
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
	v, err := viewSAMLProvider(p.id, sp)
	if err != nil {
		return samlProviderView{}, toStatus(ctx, err)
	}
	return v, nil
}
