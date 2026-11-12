package grpcapi_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/cryptotest"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func keyPairMaterial(t *testing.T, key any) string {
	t.Helper()
	pub, err := ssh.NewPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func keyPairImport() *iamv1.ImportKeyPairRequest {
	return &iamv1.ImportKeyPairRequest{
		Parent: parentName, KeyName: "laptop", Region: "ap-northeast-2", RequestId: "import-1",
		PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea",
	}
}

func TestKeyPairCreateOnce(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 497)
	b := memstore.New()
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	e := newEnvOn(t, b, &now)
	for _, typ := range []iamv1.KeyPairType{
		iamv1.KeyPairType_KEY_PAIR_TYPE_UNSPECIFIED, iamv1.KeyPairType_KEY_PAIR_TYPE_ED25519,
	} {
		req := &iamv1.CreateKeyPairRequest{
			Parent: parentName, KeyName: typ.String(), Region: "local", KeyType: typ, RequestId: typ.String(),
		}
		got, err := e.keypairs.CreateKeyPair(t.Context(), req)
		if err != nil {
			t.Fatal(err)
		}
		private, err := ssh.ParsePrivateKey([]byte(got.GetPrivateKeyMaterial()))
		if err != nil {
			t.Fatalf("Create did not return a valid private key: %v", err)
		}
		if strings.TrimSpace(string(ssh.MarshalAuthorizedKey(private.PublicKey()))) !=
			got.GetKeyPair().GetSpec().GetPublicKey() {
			t.Fatal("private and public key do not match")
		}
		if typ == iamv1.KeyPairType_KEY_PAIR_TYPE_UNSPECIFIED {
			public, ok := private.PublicKey().(ssh.CryptoPublicKey)
			if !ok {
				t.Fatal("RSA signer has no crypto public key")
			}
			key, ok := public.CryptoPublicKey().(*rsa.PublicKey)
			if !ok || key.N.BitLen() != 2048 {
				t.Fatal("default key is not RSA 2048")
			}
		}
		for _, replica := range []*env{e, newEnvOn(t, b, &now)} {
			_, err := replica.keypairs.CreateKeyPair(t.Context(), req)
			wantAWS(t, err, codes.AlreadyExists, "InvalidKeyPair.Duplicate")
			changed := proto.CloneOf(req)
			changed.Labels = map[string]string{"changed": "yes"}
			_, err = replica.keypairs.CreateKeyPair(t.Context(), changed)
			wantAWS(t, err, codes.Aborted, "IdempotentParameterMismatch")
			read, err := replica.keypairs.GetKeyPair(t.Context(), &iamv1.GetKeyPairRequest{
				Name: got.GetKeyPair().GetName(),
			})
			if err != nil || !proto.Equal(read, got.GetKeyPair()) {
				t.Fatalf("Get did not return the public resource: %v", err)
			}
			list, err := replica.keypairs.ListKeyPairs(t.Context(), &iamv1.ListKeyPairsRequest{Parent: parentName})
			if err != nil {
				t.Fatal(err)
			}
			wire, err := proto.Marshal(list)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(wire), "PRIVATE KEY") || strings.Contains(string(wire), got.GetPrivateKeyMaterial()) {
				t.Fatal("List leaked the private key")
			}
		}
		raw, err := store.List[iam.KeyPair](t.Context(), store.Scoped(b, proj))
		if err != nil {
			t.Fatal(err)
		}
		data, err := json.Marshal(raw)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "PRIVATE KEY") || strings.Contains(string(data), got.GetPrivateKeyMaterial()) {
			t.Fatal("store leaked the private key")
		}
	}
}

func TestKeyPairImportFormats(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 497)
	e := newEnv(t)
	ed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, material string
		ok             bool
	}{
		{"ed25519", keyPairMaterial(t, ed), true},
		{"comment", keyPairMaterial(t, ed) + " laptop", true},
		{"ecdsa", keyPairMaterial(t, &ec.PublicKey), false},
		{"garbage", "secret garbage", false},
		{"private", "-----BEGIN PRIVATE KEY-----\nsecret", false},
		{"two keys", keyPairMaterial(t, ed) + "\n" + keyPairMaterial(t, ed), false},
		{"options", "restrict " + keyPairMaterial(t, ed), false},
	}
	for _, bits := range []int{512, 1023, 1024, 2048, 4096, 4097, 8192} {
		n := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), big.NewInt(1))
		cases = append(cases, struct {
			name, material string
			ok             bool
		}{"rsa-" + strconv.Itoa(bits), keyPairMaterial(t, &rsa.PublicKey{N: n, E: 65537}), bits >= 1024 && bits <= 4096})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := keyPairImport()
			req.KeyName, req.RequestId, req.PublicKey = c.name, c.name, c.material
			op, err := e.keypairs.ImportKeyPair(t.Context(), req)
			if !c.ok {
				wantAWS(t, err, codes.InvalidArgument, "InvalidKey.Format")
				if strings.Contains(err.Error(), c.material) {
					t.Fatal("wire error echoed material")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			k := unpack(t, op, &iamv1.KeyPair{})
			if strings.HasSuffix(k.GetSpec().GetPublicKey(), " laptop") ||
				k.GetStatus().GetObserved().GetGeneration() != 1 || len(k.GetStatus().GetFingerprintSha256()) != 64 {
				t.Fatal("import did not canonicalize or populate status")
			}
		})
	}
}

func TestKeyPairLifecycleReplay(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) store.Backend
	}{{"memory", func(*testing.T) store.Backend { return memstore.New() }}, {"etcd", etcdBackend}} {
		t.Run(backend.name, func(t *testing.T) {
			b := backend.open(t)
			now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
			e := newEnvOn(t, b, &now)
			req := keyPairImport()
			op, err := e.keypairs.ImportKeyPair(t.Context(), req)
			if err != nil {
				t.Fatal(err)
			}
			k := unpack(t, op, &iamv1.KeyPair{})
			replica := newEnvOn(t, b, &now)
			again, err := replica.keypairs.ImportKeyPair(t.Context(), req)
			if err != nil || !proto.Equal(op, again) {
				t.Fatalf("restart replay changed: %v", err)
			}
			changed := proto.CloneOf(req)
			changed.KeyName = "other"
			_, err = replica.keypairs.ImportKeyPair(t.Context(), changed)
			wantAWS(t, err, codes.Aborted, "IdempotentParameterMismatch")
			changed = proto.CloneOf(req)
			changed.RequestId = ""
			_, err = replica.keypairs.ImportKeyPair(t.Context(), changed)
			wantAWS(t, err, codes.AlreadyExists, "InvalidKeyPair.Duplicate")
			for _, edit := range []func(*iamv1.ImportKeyPairRequest){
				func(r *iamv1.ImportKeyPairRequest) { r.Region = "other-region" },
				func(r *iamv1.ImportKeyPairRequest) { r.KeyName = "Laptop" },
				func(r *iamv1.ImportKeyPairRequest) { r.Parent = "projects/other" },
			} {
				r := proto.CloneOf(req)
				r.RequestId = ""
				edit(r)
				if _, err := replica.keypairs.ImportKeyPair(t.Context(), r); err != nil {
					t.Fatal(err)
				}
			}
			page, err := replica.keypairs.ListKeyPairs(t.Context(), &iamv1.ListKeyPairsRequest{
				Parent: parentName, Region: req.Region, KeyNames: []string{"Laptop", "laptop"}, PageSize: 1,
			})
			if err != nil || len(page.GetKeyPairs()) != 1 || page.GetNextPageToken() == "" {
				t.Fatalf("first page: %v", err)
			}
			last, err := replica.keypairs.ListKeyPairs(t.Context(), &iamv1.ListKeyPairsRequest{
				Parent: parentName, Region: req.Region, KeyNames: []string{"Laptop", "laptop"},
				PageSize: 1, PageToken: page.GetNextPageToken(),
			})
			if err != nil || len(last.GetKeyPairs()) != 1 || last.GetNextPageToken() != "" ||
				last.GetKeyPairs()[0].GetName() == page.GetKeyPairs()[0].GetName() {
				t.Fatalf("second page: %v", err)
			}
			del := &iamv1.DeleteKeyPairRequest{Name: k.GetName(), Etag: "stale"}
			_, err = e.keypairs.DeleteKeyPair(t.Context(), del)
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			del.Etag, del.RequestId = k.GetEtag(), "delete-1"
			deleted, err := e.keypairs.DeleteKeyPair(t.Context(), del)
			if err != nil {
				t.Fatal(err)
			}
			again, err = replica.keypairs.DeleteKeyPair(t.Context(), del)
			if err != nil || !proto.Equal(deleted, again) {
				t.Fatalf("delete replay changed: %v", err)
			}
			del.AllowMissing = true
			_, err = replica.keypairs.DeleteKeyPair(t.Context(), del)
			wantAWS(t, err, codes.Aborted, "IdempotentParameterMismatch")
			del.RequestId, del.Etag = "", ""
			if _, err := replica.keypairs.DeleteKeyPair(t.Context(), del); err != nil {
				t.Fatal(err)
			}
			_, err = replica.keypairs.GetKeyPair(t.Context(), &iamv1.GetKeyPairRequest{Name: k.GetName()})
			wantAWS(t, err, codes.NotFound, "InvalidKeyPair.NotFound")
			hidden, err := replica.keypairs.ListKeyPairs(t.Context(), &iamv1.ListKeyPairsRequest{
				Parent: parentName, Region: req.Region, KeyNames: []string{req.KeyName},
			})
			if err != nil || len(hidden.GetKeyPairs()) != 0 {
				t.Fatalf("deleted key pair was listed: %v", err)
			}
			del.AllowMissing = false
			_, err = replica.keypairs.DeleteKeyPair(t.Context(), del)
			wantAWS(t, err, codes.NotFound, "InvalidKeyPair.NotFound")
			changed.RequestId = "new-import"
			if _, err := replica.keypairs.ImportKeyPair(t.Context(), changed); err != nil {
				t.Fatalf("deleted name cannot be reused: %v", err)
			}
		})
	}
}

func TestKeyPairConcurrentNames(t *testing.T) {
	b := etcdBackend(t)
	now := time.Now().UTC()
	es := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Go(func() {
			r := keyPairImport()
			r.RequestId = ""
			_, err := es[i%2].keypairs.ImportKeyPair(t.Context(), r)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	success := 0
	for err := range errs {
		if err == nil {
			success++
		} else {
			wantAWS(t, err, codes.AlreadyExists, "InvalidKeyPair.Duplicate")
		}
	}
	if success != 1 {
		t.Fatalf("created %d pairs under the same regional name", success)
	}
}

func TestKeyPairValidationAndAuthorization(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{"", strings.Repeat("x", 256), "\xc3\xa9"} {
		req := keyPairImport()
		req.KeyName = name
		_, err := e.keypairs.ImportKeyPair(t.Context(), req)
		wantAWS(t, err, codes.InvalidArgument, "InvalidParameterValue")
	}
	for _, region := range []string{"", "1region", "Region_1", strings.Repeat("a", 64)} {
		req := keyPairImport()
		req.Region = region
		_, err := e.keypairs.ImportKeyPair(t.Context(), req)
		wantAWS(t, err, codes.InvalidArgument, "InvalidParameterValue")
	}
	_, err := e.keypairs.GetKeyPair(t.Context(), &iamv1.GetKeyPairRequest{Name: parentName + "/keyPairs/missing"})
	wantAWS(t, err, codes.NotFound, "InvalidKeyPair.NotFound")
	u := e.createUser(t, t.Context(), "unprivileged")
	for _, action := range []string{
		"ec2:CreateKeyPair", "ec2:ImportKeyPair", "ec2:DescribeKeyPairs", "ec2:DeleteKeyPair",
	} {
		resp, err := e.auth.Authorize(t.Context(), &iamv1.AuthorizeRequest{
			Principal: &iamv1.Principal{
				Type: iamv1.PrincipalType_PRINCIPAL_TYPE_USER, Project: proj, Resource: u.GetName(),
				Arn: u.GetStatus().GetArn(), UniqueId: u.GetStatus().GetUniqueId(),
			}, Action: action, Resources: []string{"*"},
		})
		if err != nil || resp.GetDecision() != iamv1.Decision_DECISION_DENY_IMPLICIT {
			t.Fatalf("unauthorized %s allowed: %v", action, err)
		}
	}
	b := failingList{memstore.New(), iam.KindKeyPair, errors.New("backend down")}
	now := time.Now().UTC()
	failed := newEnvOn(t, b, &now)
	_, err = failed.keypairs.ListKeyPairs(t.Context(), &iamv1.ListKeyPairsRequest{Parent: parentName})
	if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "backend down") {
		t.Fatalf("want internal error without backend detail: %v", err)
	}
}

func TestKeyPairCrashReplay(t *testing.T) {
	for _, lost := range []bool{false, true} {
		for n := 1; n <= 5; n++ {
			t.Run(fmt.Sprintf("write%d/lost=%v", n, lost), func(t *testing.T) {
				b := &crashing{Backend: memstore.New()}
				now := time.Now().UTC()
				e := newEnvOn(t, b, &now)
				b.arm(n, lost)
				if _, err := e.keypairs.ImportKeyPair(t.Context(), keyPairImport()); err != nil &&
					status.Code(err) != codes.Internal {
					t.Fatal(err)
				}
				b.revive()
				now = now.Add(membershipLease)
				replica := newEnvOn(t, b, &now)
				op, err := replica.keypairs.ImportKeyPair(t.Context(), keyPairImport())
				if err != nil {
					t.Fatal(err)
				}
				k := unpack(t, op, &iamv1.KeyPair{})
				list, err := replica.keypairs.ListKeyPairs(t.Context(), &iamv1.ListKeyPairsRequest{Parent: parentName})
				if err != nil || len(list.GetKeyPairs()) != 1 {
					t.Fatalf("crash left duplicate or visible pending pairs: %v", err)
				}
				b.arm(3, lost)
				del := &iamv1.DeleteKeyPairRequest{Name: k.GetName(), RequestId: "crashed-delete"}
				if _, err := replica.keypairs.DeleteKeyPair(t.Context(), del); err != nil &&
					status.Code(err) != codes.Internal {
					t.Fatal(err)
				}
				b.revive()
				now = now.Add(membershipLease)
				if _, err := newEnvOn(t, b, &now).keypairs.DeleteKeyPair(t.Context(), del); err != nil {
					t.Fatalf("delete lost its durable token: %v", err)
				}
			})
		}
	}
}

func TestKeyPairLostNameLock(t *testing.T) {
	b := &stealBeforeActivate{Backend: memstore.New(), kind: iam.KindKeyPair}
	now := time.Now().UTC()
	slow, fast := newEnvOn(t, b, &now), newEnvOn(t, b, &now)
	b.steal = func() {
		now = now.Add(membershipLease)
		r := keyPairImport()
		r.RequestId = "winner"
		if _, err := fast.keypairs.ImportKeyPair(t.Context(), r); err != nil {
			t.Error(err)
		}
	}
	_, err := slow.keypairs.ImportKeyPair(t.Context(), keyPairImport())
	wantAWS(t, err, codes.Aborted, "ConcurrentModification")
	list, err := fast.keypairs.ListKeyPairs(t.Context(), &iamv1.ListKeyPairsRequest{Parent: parentName})
	if err != nil || len(list.GetKeyPairs()) != 1 {
		t.Fatalf("writer without the name lock published: %v", err)
	}
	all, err := store.List[iam.KeyPair](t.Context(), store.Scoped(b, proj))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range all {
		if v.Object.Pending {
			_, err := fast.keypairs.GetKeyPair(t.Context(), &iamv1.GetKeyPairRequest{
				Name: parentName + "/keyPairs/" + v.Object.ID,
			})
			wantAWS(t, err, codes.NotFound, "InvalidKeyPair.NotFound")
		}
	}
}

var awsKeyPairID = regexp.MustCompile(`^key-[0-9a-f]{17}$`)

func TestKeyPairIDsAreAWSShaped(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 499)
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	e := newEnvOn(t, memstore.New(), &now)
	created, err := e.keypairs.CreateKeyPair(t.Context(), &iamv1.CreateKeyPairRequest{
		Parent: parentName, KeyName: "created", Region: "local",
		KeyType: iamv1.KeyPairType_KEY_PAIR_TYPE_ED25519,
	})
	if err != nil {
		t.Fatal(err)
	}
	op, err := e.keypairs.ImportKeyPair(t.Context(), keyPairImport())
	if err != nil {
		t.Fatal(err)
	}
	imported := unpack(t, op, &iamv1.KeyPair{})
	for _, name := range []string{created.GetKeyPair().GetName(), imported.GetName()} {
		if id := name[strings.LastIndex(name, "/")+1:]; !awsKeyPairID.MatchString(id) {
			t.Errorf("minted id %q is not key- and 17 hex digits", id)
		}
	}
}

func TestKeyPairLegacyIDStaysReadable(t *testing.T) {
	b := memstore.New()
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	e := newEnvOn(t, b, &now)
	op, err := e.keypairs.ImportKeyPair(t.Context(), keyPairImport())
	if err != nil {
		t.Fatal(err)
	}
	minted := unpack(t, op, &iamv1.KeyPair{})
	scoped := store.Scoped(b, proj)
	mintedID := minted.GetName()[strings.LastIndex(minted.GetName(), "/")+1:]
	stored, err := store.Get[iam.KeyPair](t.Context(), scoped, mintedID)
	if err != nil {
		t.Fatal(err)
	}
	legacy := stored.Object
	legacy.ID, legacy.Name = "key-"+strings.Repeat("0a", 16), "legacy"
	if _, err := store.Create(t.Context(), scoped, legacy); err != nil {
		t.Fatal(err)
	}
	name := parentName + "/keyPairs/" + legacy.ID
	got, err := e.keypairs.GetKeyPair(t.Context(), &iamv1.GetKeyPairRequest{Name: name})
	if err != nil || got.GetSpec().GetKeyName() != "legacy" {
		t.Fatalf("Get of a 32-hex id: %v", err)
	}
	list, err := e.keypairs.ListKeyPairs(t.Context(), &iamv1.ListKeyPairsRequest{
		Parent: parentName, KeyNames: []string{"legacy"},
	})
	if err != nil || len(list.GetKeyPairs()) != 1 || list.GetKeyPairs()[0].GetName() != name {
		t.Fatalf("List of a 32-hex id: %v", err)
	}
	if _, err := e.keypairs.DeleteKeyPair(t.Context(), &iamv1.DeleteKeyPairRequest{Name: name}); err != nil {
		t.Fatalf("Delete of a 32-hex id: %v", err)
	}
	_, err = e.keypairs.GetKeyPair(t.Context(), &iamv1.GetKeyPairRequest{Name: name})
	wantAWS(t, err, codes.NotFound, "InvalidKeyPair.NotFound")
}

func TestKeyPairIDCollisionIsRefused(t *testing.T) {
	b := memstore.New()
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	e := newEnvOn(t, b, &now)
	cryptotest.SetGlobalRandom(t, 499)
	op, err := e.keypairs.ImportKeyPair(t.Context(), keyPairImport())
	if err != nil {
		t.Fatal(err)
	}
	first := unpack(t, op, &iamv1.KeyPair{})
	cryptotest.SetGlobalRandom(t, 499)
	second := keyPairImport()
	second.KeyName, second.RequestId = "desktop", "import-2"
	_, err = e.keypairs.ImportKeyPair(t.Context(), second)
	wantAWS(t, err, codes.AlreadyExists, "EntityAlreadyExists")
	read, err := e.keypairs.GetKeyPair(t.Context(), &iamv1.GetKeyPairRequest{Name: first.GetName()})
	if err != nil || !proto.Equal(read, first) {
		t.Fatalf("a colliding create changed the first key pair: %v", err)
	}
}
