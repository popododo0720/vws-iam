package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// oidcProviderView is an OpenID Connect provider with its ARN.
type oidcProviderView struct {
	Provider iam.OIDCProvider
	ARN      string
}

// createOIDCProvider is IAM CreateOpenIDConnectProvider: it creates the
// OpenID Connect provider for issuer url in project pid, with its client
// ids, server certificate thumbprints and tags, and returns it with its
// ARN (oidc-provider/ and the URL without https://).
//
// A bad project id, a Url outside 1 to 255 characters, a client id
// outside 1 to 255 characters, a thumbprint that is not 40 characters or
// more than 50 tags is ValidationError. A Url that is not an https issuer
// (iam.CheckOIDCProviderURL: a DNS host, no port, user info, query or
// fragment, every % an escape of two hex digits), a thumbprint that is not hex, a client id that is not UTF-8
// and a tag outside the AWS tag rules are InvalidInput. A repeated client
// id or thumbprint (thumbprints compared in any case) is kept once, and of
// a repeated tag key the last value; more than 100 client ids or 5
// thumbprints after that is LimitExceeded. All of these are answered
// before any store access. No thumbprint is stored as none: AWS then
// fetches the IdP's top intermediate CA thumbprint, which needs the key
// retrieval of a later part of #208.
//
// A Url already registered (compared exactly, as OpenID Connect compares
// issuers, so one differing only in case is another provider) is
// EntityAlreadyExists and the
// stored provider stays: the create is one store create, so of racing
// requests on any replica exactly one makes the provider, and a retry
// after a lost response is EntityAlreadyExists, as in AWS. A request that
// was canceled or whose deadline passed writes nothing. A store failure is
// ServiceFailure (ServiceUnavailable when the store is unavailable), the
// fault AWS documents. Authorization (iam:CreateOpenIDConnectProvider) is
// console-api's.
//
// TODO(#208): the OpenIdConnectProvidersPerAccount quota, and serve this as
// an RPC once vws-proto carries CreateOpenIDConnectProvider.
func (s *Server) createOIDCProvider(
	ctx context.Context, pid, url string, clientIDs, thumbprints []string, tags []*iamv1.Tag,
) (oidcProviderView, error) {
	if !iam.ValidProject(pid) {
		return oidcProviderView{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	if n := utf8.RuneCountInString(url); n < 1 || n > iam.MaxOIDCProviderURLLen {
		return oidcProviderView{}, invalidSpec("url must be 1 to " + strconv.Itoa(iam.MaxOIDCProviderURLLen) + " characters")
	}
	if len(tags) > iam.MaxOIDCProviderTags {
		return oidcProviderView{}, invalidSpec("tags must have at most " + strconv.Itoa(iam.MaxOIDCProviderTags) + " items")
	}
	for _, id := range clientIDs {
		if n := utf8.RuneCountInString(id); n < 1 || n > iam.MaxOIDCClientIDLen {
			return oidcProviderView{}, invalidSpec("each clientIDList member must be 1 to " +
				strconv.Itoa(iam.MaxOIDCClientIDLen) + " characters")
		}
	}
	if err := checkOIDCThumbprintLengths(thumbprints); err != nil {
		return oidcProviderView{}, err
	}
	if err := iam.CheckOIDCProviderURL(url); err != nil {
		return oidcProviderView{}, invalidInput(err.Error())
	}
	for _, id := range clientIDs {
		if !iam.ValidOIDCClientID(id) {
			return oidcProviderView{}, invalidInput("a client id is not valid UTF-8")
		}
	}
	if err := checkOIDCThumbprintHex(thumbprints); err != nil {
		return oidcProviderView{}, err
	}
	var kept map[string]string
	if len(tags) > 0 {
		kept = make(map[string]string, len(tags))
	}
	for _, tag := range tags {
		if err := iam.CheckTag(tag.GetKey(), tag.GetValue()); err != nil {
			return oidcProviderView{}, invalidInput(err.Error())
		}
		kept[tag.GetKey()] = tag.GetValue()
	}
	clientIDs = uniqueBy(clientIDs, func(id string) string { return id })
	thumbprints = uniqueBy(thumbprints, strings.ToLower)
	if len(clientIDs) > iam.MaxOIDCClientIDs {
		return oidcProviderView{}, quota("Cannot exceed quota for ClientIdsPerOpenIdConnectProvider: " +
			strconv.Itoa(iam.MaxOIDCClientIDs))
	}
	if len(thumbprints) > iam.MaxOIDCThumbprints {
		return oidcProviderView{}, quota("Cannot exceed quota for ThumbprintsPerOpenIdConnectProvider: " +
			strconv.Itoa(iam.MaxOIDCThumbprints))
	}
	op := iam.OIDCProvider{
		Meta: iam.Meta{UID: iam.NewUID(), Generation: 1}, URL: url, ClientIDs: clientIDs,
		Thumbprints: thumbprints, Tags: kept, Created: s.now().UTC(),
	}
	if err := op.Validate(); err != nil {
		return oidcProviderView{}, invalidSpec(err.Error())
	}
	if err := ctx.Err(); err != nil {
		return oidcProviderView{}, toStatus(ctx, err) // the caller is gone; write nothing
	}
	p := s.project(pid)
	_, err := store.Create(ctx, p.b, op)
	if errors.Is(err, store.ErrExists) {
		return oidcProviderView{}, alreadyExists("Provider with url " + url + " already exists.")
	}
	if err != nil {
		return oidcProviderView{}, readFailure(ctx, err)
	}
	return oidcProviderView{Provider: op, ARN: iam.OIDCProviderARN(p.id, op)}, nil
}

// checkOIDCThumbprintLengths is ValidationError for a thumbprint that is
// not 40 characters.
func checkOIDCThumbprintLengths(thumbprints []string) error {
	for _, tp := range thumbprints {
		if utf8.RuneCountInString(tp) != iam.OIDCThumbprintLen {
			return invalidSpec("each thumbprintList member must be " + strconv.Itoa(iam.OIDCThumbprintLen) + " characters")
		}
	}
	return nil
}

// checkOIDCThumbprintHex is InvalidInput for a thumbprint that is not hex.
func checkOIDCThumbprintHex(thumbprints []string) error {
	for _, tp := range thumbprints {
		if !iam.ValidOIDCThumbprint(tp) {
			return invalidInput("a thumbprint is not " + strconv.Itoa(iam.OIDCThumbprintLen) + " hex digits")
		}
	}
	return nil
}

// uniqueBy is in without the items whose key an earlier item has, in
// order. An empty in is nil.
func uniqueBy(in []string, key func(string) string) []string {
	var out []string
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		if k := key(v); !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}

// OpenID Connect provider ARN bounds of the AWS OpenIDConnectProviderArn
// parameter.
const (
	minOIDCProviderARNLen = 20
	maxOIDCProviderARNLen = 2048
)

// oidcProviderURL returns the issuer URL an OpenIDConnectProviderArn
// names and whether it is of project pid. An ARN outside 20 to 2048
// characters is ValidationError; one that is not an OIDC provider ARN
// (arn:vws:iam::<project>:oidc-provider/<host/path> whose https URL
// CreateOpenIDConnectProvider would accept) is InvalidInput, never
// echoing the ARN.
func oidcProviderURL(pid, arn string) (url string, here bool, err error) {
	if n := utf8.RuneCountInString(arn); n < minOIDCProviderARNLen || n > maxOIDCProviderARNLen {
		return "", false, invalidSpec("openIDConnectProviderArn must be " + strconv.Itoa(minOIDCProviderARNLen) +
			" to " + strconv.Itoa(maxOIDCProviderARNLen) + " characters")
	}
	rest, ok := strings.CutPrefix(arn, "arn:"+iam.Partition+":iam::")
	account, resource, cut := strings.Cut(rest, ":oidc-provider/")
	url = oidcScheme + resource
	if !ok || !cut || !iam.ValidProject(account) || utf8.RuneCountInString(url) > iam.MaxOIDCProviderURLLen ||
		iam.CheckOIDCProviderURL(url) != nil {
		return "", false, invalidInput("openIDConnectProviderArn is not an OpenID Connect provider ARN")
	}
	return url, account == pid, nil
}

const oidcScheme = "https://"

func noOIDCProvider(arn string) error {
	return notFound("OpenIDConnect Provider not found for arn " + arn)
}

// getOIDCProvider is IAM GetOpenIDConnectProvider: the OpenID Connect
// provider arn names in project pid, with its ARN, as stored. The AWS Url
// element is iam.OIDCProviderResource of its URL, the URL without
// https://, as AWS answers.
//
// A bad project id or an ARN outside 20 to 2048 characters is
// ValidationError and an ARN that is not an OIDC provider ARN
// InvalidInput, both before any store access. An ARN of another account
// and an unknown provider are NoSuchEntity; issuers compare exactly, so an
// ARN differing from the stored one only in case names another, unknown
// provider. A store failure is ServiceFailure (ServiceUnavailable when the
// store is unavailable). The call only reads. Authorization
// (iam:GetOpenIDConnectProvider) is console-api's.
//
// TODO(#208): serve this as an RPC once vws-proto carries
// GetOpenIDConnectProvider.
func (s *Server) getOIDCProvider(ctx context.Context, pid, arn string) (oidcProviderView, error) {
	if !iam.ValidProject(pid) {
		return oidcProviderView{}, invalidID("project " + quote(pid) + " is not a project id")
	}
	url, here, err := oidcProviderURL(pid, arn)
	if err != nil {
		return oidcProviderView{}, err
	}
	if !here {
		return oidcProviderView{}, noOIDCProvider(arn)
	}
	p := s.project(pid)
	cur, err := store.Get[iam.OIDCProvider](ctx, p.b, iam.OIDCProviderKey(url))
	if errors.Is(err, store.ErrNotFound) {
		return oidcProviderView{}, noOIDCProvider(arn)
	}
	if err != nil {
		return oidcProviderView{}, readFailure(ctx, err)
	}
	return oidcProviderView{Provider: cur.Object, ARN: iam.OIDCProviderARN(p.id, cur.Object)}, nil
}

// listOIDCProviders is IAM ListOpenIDConnectProviders: the ARNs of every
// OpenID Connect provider of project pid, in byte order. AWS pages nothing
// here, so neither does this, and as in AWS the entries carry nothing but
// the ARN.
//
// A bad project id is ValidationError before any store access. No
// provider is an empty list. A store failure is ServiceFailure
// (ServiceUnavailable when the store is unavailable). The call only reads.
// Authorization (iam:ListOpenIDConnectProviders) is console-api's.
//
// TODO(#208): serve this as an RPC once vws-proto carries
// ListOpenIDConnectProviders.
func (s *Server) listOIDCProviders(ctx context.Context, pid string) ([]string, error) {
	if !iam.ValidProject(pid) {
		return nil, invalidID("project " + quote(pid) + " is not a project id")
	}
	p := s.project(pid)
	all, err := store.List[iam.OIDCProvider](ctx, p.b)
	if err != nil {
		return nil, readFailure(ctx, err)
	}
	out := make([]string, 0, len(all))
	for _, cur := range all {
		out = append(out, iam.OIDCProviderARN(p.id, cur.Object))
	}
	slices.Sort(out)
	return out, nil
}

// deleteOIDCProvider is IAM DeleteOpenIDConnectProvider: it deletes the
// OpenID Connect provider arn names in project pid. Roles that trust it
// are left as they are, as in AWS.
//
// The argument errors are those of getOIDCProvider, before any store
// access. AWS documents the call as idempotent: a provider that does not
// exist (unknown, already deleted, or named by an ARN of another account,
// which is never touched) succeeds without a write, so a retry after a
// lost response and every one of racing deletes on any replica succeed,
// and the provider is deleted once. The delete is conditional on the
// version read: a provider written in between is read again, up to
// maxDeleteAttempts, then ConcurrentModification and it stays. A request
// that was canceled or whose deadline passed deletes nothing. A store
// failure is ServiceFailure (ServiceUnavailable when the store is
// unavailable). Authorization (iam:DeleteOpenIDConnectProvider) is
// console-api's.
//
// TODO(#208): serve this as an RPC once vws-proto carries
// DeleteOpenIDConnectProvider.
func (s *Server) deleteOIDCProvider(ctx context.Context, pid, arn string) error {
	if !iam.ValidProject(pid) {
		return invalidID("project " + quote(pid) + " is not a project id")
	}
	url, here, err := oidcProviderURL(pid, arn)
	if err != nil || !here {
		return err
	}
	p := s.project(pid)
	key := iam.OIDCProviderKey(url)
	for attempt := 1; ; attempt++ {
		cur, err := store.Get[iam.OIDCProvider](ctx, p.b, key)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return readFailure(ctx, err)
		}
		if err := ctx.Err(); err != nil {
			return toStatus(ctx, err) // the caller is gone; delete nothing
		}
		err = store.Delete[iam.OIDCProvider](ctx, p.b, key, cur.Version)
		switch {
		case err == nil, errors.Is(err, store.ErrNotFound):
			return nil
		case errors.Is(err, store.ErrConflict) && attempt < maxDeleteAttempts:
			continue
		default:
			return readFailure(ctx, err)
		}
	}
}

// oidcProviderArg checks the arguments every call on an existing OpenID
// Connect provider takes: a bad project id is ValidationError, an ARN
// fault is that of oidcProviderURL, and an ARN of another account is
// NoSuchEntity. It returns the project and the issuer URL, touching no
// store.
func (s *Server) oidcProviderArg(pid, arn string) (project, string, error) {
	if !iam.ValidProject(pid) {
		return project{}, "", invalidID("project " + quote(pid) + " is not a project id")
	}
	url, here, err := oidcProviderURL(pid, arn)
	if err != nil {
		return project{}, "", err
	}
	if !here {
		return project{}, "", noOIDCProvider(arn)
	}
	return s.project(pid), url, nil
}

// checkOIDCClientID is ValidationError for a ClientID outside 1 to 255
// characters and InvalidInput for one that is not UTF-8.
func checkOIDCClientID(id string) error {
	if n := utf8.RuneCountInString(id); n < 1 || n > iam.MaxOIDCClientIDLen {
		return invalidSpec("clientID must be 1 to " + strconv.Itoa(iam.MaxOIDCClientIDLen) + " characters")
	}
	if !iam.ValidOIDCClientID(id) {
		return invalidInput("the client id is not valid UTF-8")
	}
	return nil
}

// changeOIDCProvider reads the OpenID Connect provider url of project p
// (missing when there is none), applies change to it and writes it at the
// version read with the generation moved, and returns the provider as
// stored. When change reports nothing to change, nothing is written. A
// provider written in between is read again and changed anew, up to
// maxDeleteAttempts, then the store conflict. A changed provider that
// does not validate is the caller's input (invalidSpec), unless the
// stored one does not validate either, which is an internal error. A
// request that was canceled or whose deadline passed writes nothing. A
// store failure is returned as is, for the caller to map.
func (s *Server) changeOIDCProvider(
	ctx context.Context, p project, url string, missing error, change func(*iam.OIDCProvider) (bool, error),
) (iam.OIDCProvider, error) {
	key := iam.OIDCProviderKey(url)
	for attempt := 1; ; attempt++ {
		cur, err := store.Get[iam.OIDCProvider](ctx, p.b, key)
		if errors.Is(err, store.ErrNotFound) {
			return iam.OIDCProvider{}, missing
		}
		if err != nil {
			return iam.OIDCProvider{}, err
		}
		op := cur.Object
		changed, err := change(&op)
		if err != nil || !changed {
			return cur.Object, err
		}
		op.Generation++
		if err := op.Validate(); err != nil {
			if cur.Object.Validate() != nil {
				return iam.OIDCProvider{}, fmt.Errorf("stored OpenID Connect provider does not validate: %w", err)
			}
			return iam.OIDCProvider{}, invalidSpec(err.Error())
		}
		if err := ctx.Err(); err != nil {
			return iam.OIDCProvider{}, fmt.Errorf("OpenID Connect provider: %w", err) // the caller is gone; write nothing
		}
		_, err = store.Update(ctx, p.b, op, cur.Version)
		switch {
		case err == nil:
			return op, nil
		case errors.Is(err, store.ErrConflict) && attempt < maxDeleteAttempts:
			continue
		case errors.Is(err, store.ErrNotFound):
			return iam.OIDCProvider{}, missing
		default:
			return iam.OIDCProvider{}, err
		}
	}
}

// updateOIDCProviderThumbprint is IAM UpdateOpenIDConnectProviderThumbprint:
// it replaces the whole server certificate thumbprint list of the OpenID
// Connect provider arn names in project pid.
//
// The ARN errors are those of getOIDCProvider. A thumbprint that is not 40
// characters is ValidationError and one that is not hex InvalidInput. A
// thumbprint repeated in any case is kept once, in order, and more than 5
// after that is InvalidInput, as AWS documents no LimitExceeded for this
// call. All of these are answered before any store access. An empty list
// is accepted and leaves the provider with no thumbprint, as
// CreateOpenIDConnectProvider allows; the request cannot tell a missing
// list from an empty one. An unknown provider is NoSuchEntity (unlike
// delete, this call is not idempotent on a missing provider). A list equal
// to the stored one writes nothing, so a retry after a lost response
// succeeds unchanged. The write moves the generation and keeps the URL,
// UID, client ids, tags and creation time, at the version read (a provider
// written in between is read again, keeping that writer's change, up to
// maxDeleteAttempts, then ConcurrentModification). A request that was
// canceled or whose deadline passed writes nothing. A store failure is
// ServiceFailure (ServiceUnavailable when the store is unavailable).
// Authorization (iam:UpdateOpenIDConnectProviderThumbprint) is
// console-api's.
//
// TODO(#208): serve this as an RPC once vws-proto carries
// UpdateOpenIDConnectProviderThumbprint.
func (s *Server) updateOIDCProviderThumbprint(ctx context.Context, pid, arn string, thumbprints []string) error {
	p, url, err := s.oidcProviderArg(pid, arn)
	if err != nil {
		return err
	}
	if err := checkOIDCThumbprintLengths(thumbprints); err != nil {
		return err
	}
	if err := checkOIDCThumbprintHex(thumbprints); err != nil {
		return err
	}
	thumbprints = uniqueBy(thumbprints, strings.ToLower)
	if len(thumbprints) > iam.MaxOIDCThumbprints {
		return invalidInput("Cannot exceed quota for ThumbprintsPerOpenIdConnectProvider: " +
			strconv.Itoa(iam.MaxOIDCThumbprints))
	}
	_, err = s.changeOIDCProvider(ctx, p, url, noOIDCProvider(arn), func(op *iam.OIDCProvider) (bool, error) {
		if slices.Equal(op.Thumbprints, thumbprints) {
			return false, nil
		}
		op.Thumbprints = thumbprints
		return true, nil
	})
	return readFailure(ctx, err)
}

// addClientIDToOIDCProvider is IAM AddClientIDToOpenIDConnectProvider: it
// adds a client id to the OpenID Connect provider arn names in project
// pid, after the ones it has.
//
// The ARN errors are those of getOIDCProvider. A ClientID outside 1 to 255
// characters is ValidationError and one that is not UTF-8 InvalidInput,
// before any store access. An unknown provider is NoSuchEntity. As AWS
// documents, adding a client id the provider already has succeeds, and
// writes nothing. A provider that would hold more than 100 client ids is
// LimitExceeded and is not written. The write, the retries, a canceled
// request and a store failure are as in updateOIDCProviderThumbprint.
// Authorization (iam:AddClientIDToOpenIDConnectProvider) is console-api's.
//
// TODO(#208): serve this as an RPC once vws-proto carries
// AddClientIDToOpenIDConnectProvider.
func (s *Server) addClientIDToOIDCProvider(ctx context.Context, pid, arn, clientID string) error {
	p, url, err := s.oidcProviderArg(pid, arn)
	if err != nil {
		return err
	}
	if err := checkOIDCClientID(clientID); err != nil {
		return err
	}
	_, err = s.changeOIDCProvider(ctx, p, url, noOIDCProvider(arn), func(op *iam.OIDCProvider) (bool, error) {
		if slices.Contains(op.ClientIDs, clientID) {
			return false, nil
		}
		if len(op.ClientIDs) >= iam.MaxOIDCClientIDs {
			return false, quota("Cannot exceed quota for ClientIdsPerOpenIdConnectProvider: " +
				strconv.Itoa(iam.MaxOIDCClientIDs))
		}
		op.ClientIDs = append(slices.Clone(op.ClientIDs), clientID)
		return true, nil
	})
	return readFailure(ctx, err)
}

// removeClientIDFromOIDCProvider is IAM RemoveClientIDFromOpenIDConnectProvider:
// it removes a client id from the OpenID Connect provider arn names in
// project pid. Removing the last one leaves the provider with none.
//
// The argument errors, the write, the retries, a canceled request and a
// store failure are those of addClientIDToOIDCProvider. As AWS documents,
// removing a client id the provider does not have succeeds, and writes
// nothing. Authorization (iam:RemoveClientIDFromOpenIDConnectProvider) is
// console-api's.
//
// TODO(#208): serve this as an RPC once vws-proto carries
// RemoveClientIDFromOpenIDConnectProvider.
func (s *Server) removeClientIDFromOIDCProvider(ctx context.Context, pid, arn, clientID string) error {
	p, url, err := s.oidcProviderArg(pid, arn)
	if err != nil {
		return err
	}
	if err := checkOIDCClientID(clientID); err != nil {
		return err
	}
	_, err = s.changeOIDCProvider(ctx, p, url, noOIDCProvider(arn), func(op *iam.OIDCProvider) (bool, error) {
		if !slices.Contains(op.ClientIDs, clientID) {
			return false, nil
		}
		op.ClientIDs = slices.DeleteFunc(slices.Clone(op.ClientIDs), func(id string) bool { return id == clientID })
		if len(op.ClientIDs) == 0 {
			op.ClientIDs = nil
		}
		return true, nil
	})
	return readFailure(ctx, err)
}
