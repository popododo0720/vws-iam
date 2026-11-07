package samltest_test

import (
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/sts/samltest"
)

// TestMetadata: the IdP's metadata is long enough for CreateSAMLProvider,
// parses back to the IdP's entity id and certificate, and carries its
// validity only when one is given.
func TestMetadata(t *testing.T) {
	now := time.Date(2026, 11, 3, 4, 0, 0, 0, time.UTC)
	idp, err := samltest.New("https://idp.corp.test/", now)
	if err != nil {
		t.Fatal(err)
	}
	until := now.Add(48 * time.Hour)
	for _, v := range []time.Time{{}, until} {
		doc := idp.Metadata(v)
		if n := len([]rune(doc)); n < iam.MinSAMLMetadataLen {
			t.Fatalf("metadata has %d characters, want at least %d", n, iam.MinSAMLMetadataLen)
		}
		md, err := iam.ParseSAMLMetadata(doc)
		if err != nil {
			t.Fatal(err)
		}
		if md.EntityID != idp.EntityID || len(md.Certificates) != 1 || !md.Certificates[0].Equal(idp.Cert) ||
			!md.ValidUntil.Equal(v) {
			t.Fatalf("parsed %+v for validUntil %v", md, v)
		}
	}
}
