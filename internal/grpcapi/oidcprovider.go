package grpcapi

import (
	"context"
	"errors"
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
// fragment), a thumbprint that is not hex, a client id that is not UTF-8
// and a tag outside the AWS tag rules are InvalidInput. A repeated client
// id or thumbprint (thumbprints compared in any case) is kept once, and of
// a repeated tag key the last value; more than 100 client ids or 5
// thumbprints after that is LimitExceeded. All of these are answered
// before any store access. No thumbprint is stored as none: AWS then
// fetches the IdP's top intermediate CA thumbprint, which needs the key
// retrieval of a later part of #208.
//
// A Url already registered, in any case, is EntityAlreadyExists and the
// stored provider stays: the create is one store create, so of racing
// requests on any replica exactly one makes the provider, and a retry
// after a lost response is EntityAlreadyExists, as in AWS. A request that
// was canceled or whose deadline passed writes nothing. A store failure is
// InternalFailure. Authorization (iam:CreateOpenIDConnectProvider) is
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
	for _, tp := range thumbprints {
		if utf8.RuneCountInString(tp) != iam.OIDCThumbprintLen {
			return oidcProviderView{}, invalidSpec("each thumbprintList member must be " +
				strconv.Itoa(iam.OIDCThumbprintLen) + " characters")
		}
	}
	if err := iam.CheckOIDCProviderURL(url); err != nil {
		return oidcProviderView{}, invalidInput(err.Error())
	}
	for _, id := range clientIDs {
		if !iam.ValidOIDCClientID(id) {
			return oidcProviderView{}, invalidInput("a client id is not valid UTF-8")
		}
	}
	for _, tp := range thumbprints {
		if !iam.ValidOIDCThumbprint(tp) {
			return oidcProviderView{}, invalidInput("a thumbprint is not " + strconv.Itoa(iam.OIDCThumbprintLen) + " hex digits")
		}
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
		return oidcProviderView{}, toStatus(ctx, err)
	}
	return oidcProviderView{Provider: op, ARN: iam.OIDCProviderARN(p.id, op)}, nil
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
