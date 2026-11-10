package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/sigv4"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func TestBootstrapLegacyRoot(t *testing.T) {
	const id = "VWSABCDEF012389XYZAB"
	sec, err := accesskey.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := keyring(config{})
	if err != nil {
		t.Fatal(err)
	}
	b := memstore.New()
	cfg := config{getenv: envOf(map[string]string{envRootProject: "acme", envRootKeyID: id, envRootSecret: sec})}
	ctx := t.Context()
	if _, err := bootstrapRoot(ctx, b, keys, cfg); err != nil {
		t.Fatalf("import legacy root key: %v", err)
	}
	scoped := store.Scoped(b, "acme")
	first, err := store.Get[iam.AccessKey](ctx, scoped, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapRoot(ctx, b, keys, cfg); err != nil {
		t.Fatalf("repeat bootstrap: %v", err)
	}
	again, err := store.Get[iam.AccessKey](ctx, scoped, id)
	if err != nil {
		t.Fatal(err)
	}
	if again.Version != first.Version {
		t.Fatal("repeat bootstrap changed the imported key")
	}
	now := time.Now().UTC()
	date, amz := now.Format("20060102"), now.Format("20060102T150405Z")
	const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	canonical := "GET\n/\n\nhost:s3.vws.local\nx-amz-date:" + amz + "\n\nhost;x-amz-date\n" + emptyHash
	hash := sha256.Sum256([]byte(canonical))
	sts := "AWS4-HMAC-SHA256\n" + amz + "\n" + date + "/kr-1/s3/aws4_request\n" + hex.EncodeToString(hash[:])
	api := grpcapi.New(b, keys, grpcapi.WithClock(func() time.Time { return now }))
	resp, err := api.Authenticate(ctx, &iamv1.AuthenticateRequest{
		AccessKeyId: id, Date: date, Region: "kr-1", Service: "s3", CanonicalRequest: canonical,
		StringToSign: sts, Signature: sigv4.Sign([]byte(sec), date, "kr-1", "s3", sts),
	})
	if err != nil || !resp.GetIsRoot() {
		t.Fatalf("legacy root authentication: root=%v, err=%v", resp.GetIsRoot(), err)
	}
	user := iam.User{Meta: iam.Meta{UID: "alice"}, Name: "alice", ID: "alice"}
	if _, err := store.Create(ctx, scoped, user); err != nil {
		t.Fatal(err)
	}
	svc := accesskey.New(scoped, b, "acme", keys, nil)
	userKey, err := api.CreateAccessKey(ctx, &iamv1.CreateAccessKeyRequest{Parent: "projects/acme/users/alice"})
	if err != nil {
		t.Fatal(err)
	}
	keyName := userKey.GetAccessKey().GetName()
	if !strings.HasPrefix(keyName[strings.LastIndex(keyName, "/")+1:], "AKIA") {
		t.Fatalf("generated key has the wrong prefix")
	}
	if _, err := svc.Import(ctx, "alice", id, sec, false); !errors.Is(err, iam.ErrInvalid) {
		t.Fatalf("legacy IAM user key: %v", err)
	}
}
