package grpcapi_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
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
)

const oidcThumbprint = "9e99a48a9960b14926bb7f3b02e22da2b0ab7280"

func storedOIDC(t *testing.T, b store.Backend, key string) store.Versioned[iam.OIDCProvider] {
	t.Helper()
	v, err := store.Get[iam.OIDCProvider](t.Context(), store.Scoped(b, proj), key)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func oidcCount(t *testing.T, b store.Backend) int {
	t.Helper()
	all, err := store.List[iam.OIDCProvider](t.Context(), store.Scoped(b, proj))
	if err != nil {
		t.Fatal(err)
	}
	return len(all)
}

// thumbprints is n distinct thumbprints.
func thumbprints(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = strconv.Itoa(i%10) + strconv.Itoa(i/10) + oidcThumbprint[2:]
	}
	return out
}

func clientIDs(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "app-" + strconv.Itoa(i)
	}
	return out
}

// TestCreateOpenIDConnectProvider: a new provider has the requested URL,
// client ids, thumbprints and tags (the last value of a repeated key), the
// request time, a UID and generation 1; it is returned with its ARN,
// stored as returned and read by a replica started later on the same
// store. A URL already registered is EntityAlreadyExists on every replica
// and the stored provider stays; one differing only in case is another
// issuer, as is the host without the path; another project has its own
// providers. On both store backends.
func TestCreateOpenIDConnectProvider(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Date(2026, 11, 9, 4, 0, 0, 0, time.UTC)
			e := newEnvOn(t, b, &now)
			const url = "https://Token.Example.test/team"
			tags := []*iamv1.Tag{samlTag("team", "a"), samlTag("env", "prod"), samlTag("team", "b")}
			got, err := e.api.CreateOpenIDConnectProvider(t.Context(), proj, url,
				[]string{"sts.amazonaws.com", "app"}, []string{oidcThumbprint}, tags)
			if err != nil {
				t.Fatal(err)
			}
			p := got.Provider
			if p.URL != url || !slices.Equal(p.ClientIDs, []string{"sts.amazonaws.com", "app"}) ||
				!slices.Equal(p.Thumbprints, []string{oidcThumbprint}) || !p.Created.Equal(now) || p.UID == "" ||
				p.Generation != 1 || len(p.Tags) != 2 || p.Tags["team"] != "b" || p.Tags["env"] != "prod" {
				t.Fatalf("CreateOpenIDConnectProvider = %+v", p)
			}
			if want := "arn:vws:iam::" + proj + ":oidc-provider/Token.Example.test/team"; got.ARN != want {
				t.Fatalf("Arn = %q, want %q", got.ARN, want)
			}
			replica := newEnvOn(t, b, &now)
			stored := storedOIDC(t, b, iam.OIDCProviderKey(url))
			s := stored.Object
			if s.UID != p.UID || s.URL != url || !slices.Equal(s.ClientIDs, p.ClientIDs) ||
				!slices.Equal(s.Thumbprints, p.Thumbprints) || !s.Created.Equal(now) || s.Tags["team"] != "b" {
				t.Fatalf("stored %+v, want it as returned %+v", s, p)
			}
			_, err = replica.api.CreateOpenIDConnectProvider(t.Context(), proj, url, []string{"other"}, nil, nil)
			wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			again := storedOIDC(t, b, iam.OIDCProviderKey(url))
			if again.Version != stored.Version || again.Object.UID != p.UID {
				t.Fatalf("a refused create changed the provider: %+v", again.Object)
			}
			if _, err := e.api.CreateOpenIDConnectProvider(t.Context(), "other", url, nil, nil, nil); err != nil {
				t.Fatalf("same URL in another project: %v", err)
			}
			for _, other := range []string{
				"https://token.example.test/team", "https://Token.Example.test/Team", "https://Token.Example.test",
			} {
				got, err := replica.api.CreateOpenIDConnectProvider(t.Context(), proj, other, nil, nil, nil)
				if err != nil {
					t.Fatalf("%s: %v, want another provider", other, err)
				}
				if want := "arn:vws:iam::" + proj + ":oidc-provider/" + other[len("https://"):]; got.ARN != want {
					t.Fatalf("Arn = %q, want %q", got.ARN, want)
				}
				if s := storedOIDC(t, b, iam.OIDCProviderKey(other)).Object; s.URL != other {
					t.Fatalf("stored %q under the key of %q", s.URL, other)
				}
			}
			if n := oidcCount(t, b); n != 4 {
				t.Fatalf("%d providers in %s, want 4", n, proj)
			}
		})
	}
}

// TestCreateOpenIDConnectProviderLists: repeated client ids (exact) and
// thumbprints (in any case) are kept once, in order, before the counts,
// so 100 client ids and 5 thumbprints with repeats are accepted; 101 and
// 6 distinct ones are LimitExceeded and store nothing. No client id,
// thumbprint or tag stores none.
func TestCreateOpenIDConnectProviderLists(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	// APP-0 differs from app-0 in case, so it is a 101st client id.
	ids := append(clientIDs(iam.MaxOIDCClientIDs), "app-0", "app-99", "APP-0")
	tps := append(thumbprints(iam.MaxOIDCThumbprints-1), strings.ToUpper(thumbprints(1)[0]), thumbprints(2)[1])
	_, err := e.api.CreateOpenIDConnectProvider(ctx, proj, "https://a.test", ids, tps, nil)
	wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
	got, err := e.api.CreateOpenIDConnectProvider(ctx, proj, "https://a.test", ids[:len(ids)-1], tps, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Provider.ClientIDs, clientIDs(iam.MaxOIDCClientIDs)) {
		t.Fatalf("client ids %v, want app-0 to app-99 once each", got.Provider.ClientIDs)
	}
	if want := thumbprints(iam.MaxOIDCThumbprints - 1); !slices.Equal(got.Provider.Thumbprints, want) {
		t.Fatalf("thumbprints %v, want %v", got.Provider.Thumbprints, want)
	}
	six := thumbprints(iam.MaxOIDCThumbprints + 1)
	_, err = e.api.CreateOpenIDConnectProvider(ctx, proj, "https://b.test", nil, six, nil)
	wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
	_, err = e.api.CreateOpenIDConnectProvider(ctx, proj, "https://b.test", nil, thumbprints(iam.MaxOIDCThumbprints), nil)
	if err != nil {
		t.Fatalf("5 thumbprints: %v", err)
	}
	if _, err := e.api.CreateOpenIDConnectProvider(ctx, proj, "https://c.test", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	c := storedOIDC(t, b, iam.OIDCProviderKey("https://c.test")).Object
	if c.ClientIDs != nil || c.Thumbprints != nil || c.Tags != nil {
		t.Fatalf("a bare provider stored %+v", c)
	}
	if n := oidcCount(t, b); n != 3 {
		t.Fatalf("%d providers, want 3", n)
	}
}

// TestCreateOpenIDConnectProviderConcurrent: of racing creates of one URL
// on two replicas exactly one succeeds and the rest are
// EntityAlreadyExists; a retry of the winner is EntityAlreadyExists too.
// On both store backends.
func TestCreateOpenIDConnectProviderConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			const url = "https://IdP.test/X"
			errs := make([]error, 16)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					_, errs[i] = replicas[i%2].api.CreateOpenIDConnectProvider(t.Context(), proj, url,
						[]string{"racer-" + strconv.Itoa(i)}, nil, nil)
				})
			}
			wg.Wait()
			won := -1
			for i, err := range errs {
				if err != nil {
					wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
					continue
				}
				if won >= 0 {
					t.Fatal("two creates succeeded")
				}
				won = i
			}
			if won < 0 {
				t.Fatal("no create succeeded")
			}
			got := storedOIDC(t, b, iam.OIDCProviderKey(url)).Object
			if got.URL != url || !slices.Equal(got.ClientIDs, []string{"racer-" + strconv.Itoa(won)}) {
				t.Fatalf("stored %q %v, want the winner's (%d)", got.URL, got.ClientIDs, won)
			}
			_, err := replicas[0].api.CreateOpenIDConnectProvider(t.Context(), proj, url,
				[]string{"racer-" + strconv.Itoa(won)}, nil, nil)
			wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
			if n := oidcCount(t, b); n != 1 {
				t.Fatalf("%d providers stored, want 1", n)
			}
		})
	}
}

// TestCreateOpenIDConnectProviderErrors: every bad argument is answered
// with its AWS code before any store access, stores nothing, and a URL
// fault never echoes the URL; the boundary values are accepted.
func TestCreateOpenIDConnectProviderErrors(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	ctx := t.Context()
	const canary = "SECRETCANARY"
	create := func(pid, url string, ids, tps []string, tags ...*iamv1.Tag) error {
		_, err := e.api.CreateOpenIDConnectProvider(ctx, pid, url, ids, tps, tags)
		return err
	}
	const good = "https://idp.test"
	tooManyTags := make([]*iamv1.Tag, iam.MaxOIDCProviderTags+1)
	for i := range tooManyTags {
		tooManyTags[i] = samlTag("k"+strconv.Itoa(i), "v")
	}
	long := "https://" + strings.Repeat("a", iam.MaxOIDCProviderURLLen-len("https://")+1)
	type row struct {
		name, aws string
		err       error
	}
	const (
		validation = "ValidationError"
		input      = "InvalidInput"
	)
	cases := []row{
		{"bad project", validation, create("Bad_Project", good, nil, nil)},
		{"empty url", validation, create(proj, "", nil, nil)},
		{"url of 256 characters", validation, create(proj, long, nil, nil)},
		{"51 tags", validation, create(proj, good, nil, nil, tooManyTags...)},
		{"empty client id", validation, create(proj, good, []string{"app", ""}, nil)},
		{"client id of 256 characters", validation, create(proj, good, []string{strings.Repeat("é", 256)}, nil)},
		{"thumbprint of 39 characters", validation, create(proj, good, nil, []string{oidcThumbprint[:39]})},
		{"thumbprint of 41 characters", validation, create(proj, good, nil, []string{oidcThumbprint + "0"})},
		{"http url", input, create(proj, "http://idp.test/"+canary, nil, nil)},
		{"no scheme", input, create(proj, "idp.test/"+canary, nil, nil)},
		{"url with a port", input, create(proj, "https://idp.test:8443/"+canary, nil, nil)},
		{"url with user info", input, create(proj, "https://"+canary+"@idp.test", nil, nil)},
		{"url with a query", input, create(proj, "https://idp.test/?"+canary, nil, nil)},
		{"url with a fragment", input, create(proj, "https://idp.test/#"+canary, nil, nil)},
		{"url with a space", input, create(proj, "https://idp.test/"+canary+" x", nil, nil)},
		{"url with a bad host", input, create(proj, "https://"+canary+"_x.test", nil, nil)},
		{"url without a host", input, create(proj, "https:///"+canary, nil, nil)},
		{"url with a bad escape", input, create(proj, "https://idp.test/%zz"+canary, nil, nil)},
		{"url ending in %", input, create(proj, "https://idp.test/"+canary+"%", nil, nil)},
		{"client id not UTF-8", input, create(proj, good, []string{"\xff"}, nil)},
		{"thumbprint not hex", input, create(proj, good, nil, []string{"z" + oidcThumbprint[1:]})},
		{"reserved tag key", input, create(proj, good, nil, nil, samlTag("aws:team", "a"))},
		{"tag value outside the alphabet", input, create(proj, good, nil, nil, samlTag("k", "<script>"))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantAWS(t, c.err, codes.InvalidArgument, c.aws)
			if msg := status.Convert(c.err).Message(); strings.Contains(msg, canary) {
				t.Fatalf("message carries the URL: %q", msg)
			}
		})
	}
	if n := oidcCount(t, b); n != 0 {
		t.Fatalf("%d providers stored by refused requests", n)
	}

	longest := "https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) +
		"/" + strings.Repeat("d", iam.MaxOIDCProviderURLLen-len("https://")-3*64)
	if n := len(longest); n != iam.MaxOIDCProviderURLLen {
		t.Fatalf("longest URL has %d characters", n)
	}
	fifty := make([]*iamv1.Tag, iam.MaxOIDCProviderTags)
	for i := range fifty {
		fifty[i] = samlTag("k"+strconv.Itoa(i), strings.Repeat("v", 256))
	}
	for _, ok := range []struct {
		url  string
		ids  []string
		tps  []string
		tags []*iamv1.Tag
	}{
		{longest, nil, nil, nil},
		{"https://a", []string{"a", strings.Repeat("é", iam.MaxOIDCClientIDLen)}, nil, nil},
		{"https://b", nil, []string{strings.ToUpper(oidcThumbprint)}, fifty},
	} {
		if _, err := e.api.CreateOpenIDConnectProvider(ctx, proj, ok.url, ok.ids, ok.tps, ok.tags); err != nil {
			t.Errorf("%.40s: %v", ok.url, err)
		}
	}
}

// TestCreateOpenIDConnectProviderCanceled: a canceled request writes
// nothing, and the same request afterwards succeeds.
func TestCreateOpenIDConnectProviderCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := e.api.CreateOpenIDConnectProvider(canceled, proj, "https://gone.test", nil, nil, nil); err == nil {
		t.Fatal("a canceled create succeeded")
	}
	if n := oidcCount(t, b); n != 0 {
		t.Fatalf("%d providers stored by a canceled request", n)
	}
	if _, err := e.api.CreateOpenIDConnectProvider(t.Context(), proj, "https://gone.test", nil, nil, nil); err != nil {
		t.Fatalf("the same request afterwards: %v", err)
	}
}

// TestCreateOpenIDConnectProviderStoreFailure: a store that fails the
// create is ServiceFailure, the fault AWS documents, and an unavailable
// one ServiceUnavailable; neither stores a provider.
func TestCreateOpenIDConnectProviderStoreFailure(t *testing.T) {
	inner := memstore.New()
	now := time.Now().UTC()
	for _, c := range []struct {
		err  error
		code codes.Code
		aws  string
	}{
		{errors.New("boom"), codes.Internal, "ServiceFailure"},
		{store.ErrUnavailable, codes.Unavailable, "ServiceUnavailable"},
	} {
		e := newEnvOn(t, failingCreate{Backend: inner, k: iam.KindOIDCProvider, err: c.err}, &now)
		_, err := e.api.CreateOpenIDConnectProvider(t.Context(), proj, "https://idp.test", nil, nil, nil)
		wantAWS(t, err, c.code, c.aws)
	}
	if n := oidcCount(t, inner); n != 0 {
		t.Fatalf("%d providers stored", n)
	}
}
