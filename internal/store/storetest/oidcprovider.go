package storetest

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// oidcProviderLongestRoundTrip stores a provider at every AWS limit: a
// 255-character URL with a path (its key has slashes and needs the kube
// name hash fallback), 100 client ids of 255 characters and 5
// thumbprints. It is found by its key in another case, and a URL that
// differs only in case is the same provider.
func oidcProviderLongestRoundTrip(t *testing.T, b store.Backend) {
	t.Helper()
	ctx := context.Background()
	url := "https://Token.Example.test/" + strings.Repeat("p/", 100)
	url += strings.Repeat("q", iam.MaxOIDCProviderURLLen-len(url))
	p := iam.OIDCProvider{URL: url, Created: time.Unix(1700000000, 0).UTC(), Meta: iam.Meta{UID: "o-long", Generation: 1}}
	for i := range iam.MaxOIDCClientIDs {
		id := string(rune('a'+i%26)) + strings.Repeat("é", iam.MaxOIDCClientIDLen-2) + string(rune('A'+i/26))
		p.ClientIDs = append(p.ClientIDs, id)
	}
	for i := range iam.MaxOIDCThumbprints {
		p.Thumbprints = append(p.Thumbprints, strings.Repeat(string(rune('a'+i)), iam.OIDCThumbprintLen))
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("longest provider: %v", err)
	}
	if _, err := store.Create(ctx, b, p); err != nil {
		t.Fatalf("create longest OIDC provider: %v", err)
	}
	got, err := store.Get[iam.OIDCProvider](ctx, b, strings.ToUpper(p.Key()))
	if err != nil {
		t.Fatalf("get longest OIDC provider by its key in upper case: %v", err)
	}
	if a, b := mustJSON(t, got.Object), mustJSON(t, p); a != b {
		t.Fatalf("longest OIDC provider round trip:\n got %s\nwant %s", a, b)
	}
	other := p
	other.URL = strings.ToLower(p.URL)
	if _, err := store.Create(ctx, b, other); err == nil {
		t.Fatal("a URL differing only in case was stored as a second provider")
	}
}
