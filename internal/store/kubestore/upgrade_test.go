package kubestore_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
)

const (
	fixtureTag     = "sha-74a29dc"
	fixtureProject = "acme"
	fixtureKEKID   = "fixture-kek"
)

var fixtureNow = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func fixtureDir() string {
	return filepath.Join("..", "..", "..", "testdata", "upgrade", fixtureTag)
}

// TestPreviousReleaseRecordsDecode loads the custom resources that the
// previous release wrote into envtest with today's CRDs, then reads every
// kind through today's kubestore and typed helpers. Renaming, removing or
// re-encoding a stored field changes the decoded object and fails it.
func TestPreviousReleaseRecordsDecode(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set")
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "..", "..", "deploy", "crds")},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	c, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "vws-iam-upgrade-"}}
	if err := c.Create(ctx, ns); err != nil {
		t.Fatal(err)
	}
	keys, err := secret.NewKeyring(fixtureKEKID, map[string][]byte{fixtureKEKID: bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := loadFixtureCRs(t, c, ns.Name), fixtureCounts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("fixture records by kind = %v, want %v", got, want)
	}
	raw := kubestore.New(c, ns.Name)
	b := store.Scoped(raw, fixtureProject)

	t.Run("user with session revocation", func(t *testing.T) {
		want := iam.User{
			Meta: iam.Meta{
				UID: "11111111-1111-4111-8111-111111111111", Generation: 3,
				Labels: map[string]string{"team": "platform"}, Updated: fixtureNow.Add(-time.Hour), RequestID: "req-user-create",
			},
			Name: "alice", Path: "/engineering/", ID: "AIDAALICEFIXTURE0001", Created: fixtureNow.Add(-30 * 24 * time.Hour),
			AttachedPolicies:      []string{"arn:vws:iam::acme:policy/ReadOnly"},
			InlinePolicies:        map[string]string{"inline": `{"Version":"2012-10-17"}`},
			PasswordHash:          "$argon2id$v=19$m=65536,t=2,p=1$Zml4dHVyZXNhbHQ$AAAAAAAAAAAAAAAAAAAAAA",
			PasswordResetRequired: true, PasswordLastUsed: fixtureNow.Add(-2 * time.Hour),
			SessionsRevokedBefore:    fixtureNow.Add(-3 * time.Hour),
			SessionsRevokeGeneration: 2,
			SessionsRevokeRequests:   []string{"req-revoke-1", "req-revoke-2"},
		}
		readRecord(t, b, "alice", want)
	})

	t.Run("group", func(t *testing.T) {
		want := iam.Group{
			Meta: iam.Meta{UID: "22222222-2222-4222-8222-222222222222", Generation: 1, Updated: fixtureNow.Add(-time.Hour)},
			Name: "engineering", Path: "/engineering/", ID: "AGPAENGINEERINGFIX01",
			Created: fixtureNow.Add(-20 * 24 * time.Hour),
			Members: []string{"alice", "bob"}, AttachedPolicies: []string{"arn:vws:iam::acme:policy/ReadOnly"},
			InlinePolicies: map[string]string{"inline": `{"Version":"2012-10-17"}`},
		}
		readRecord(t, b, "engineering", want)
	})

	t.Run("role with session revocation", func(t *testing.T) {
		want := iam.Role{
			Meta: iam.Meta{UID: "33333333-3333-4333-8333-333333333333", Generation: 2, Updated: fixtureNow.Add(-time.Hour)},
			Name: "deployer", Path: "/engineering/", ID: "AROADEPLOYERFIXTURE1", Created: fixtureNow.Add(-10 * 24 * time.Hour),
			AssumeRolePolicy: `{"Version":"2012-10-17","Statement":[]}`,
			Description:      "fixture deployment role", MaxSessionDuration: time.Hour,
			AttachedPolicies:      []string{"arn:vws:iam::acme:policy/ReadOnly"},
			InlinePolicies:        map[string]string{"inline": `{"Version":"2012-10-17"}`},
			SessionsRevokedBefore: fixtureNow.Add(-4 * time.Hour), SessionsRevokeGeneration: 1,
			SessionsRevokeRequests: []string{"req-role-revoke"},
		}
		readRecord(t, b, "deployer", want)
	})

	t.Run("policy without tags", func(t *testing.T) {
		want := iam.Policy{
			Meta: iam.Meta{UID: "44444444-4444-4444-8444-444444444444", Generation: 2, Updated: fixtureNow.Add(-time.Hour)},
			Name: "ReadOnly", Path: "/engineering/", ID: "ANPAREADONLYFIXTURE1", Created: fixtureNow.Add(-15 * 24 * time.Hour),
			Description: "fixture read-only policy", DefaultVersion: "v2", NextVersion: 3,
			Versions: []iam.PolicyVersion{
				{ID: "v1", Document: `{"Version":"2012-10-17","Statement":[]}`, Created: fixtureNow.Add(-15 * 24 * time.Hour)},
				{
					ID:       "v2",
					Document: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`,
					Created:  fixtureNow.Add(-14 * 24 * time.Hour),
				},
			},
		}
		got := readRecord(t, b, "ReadOnly", want)
		if got.Tags != nil {
			t.Fatalf("previous-release policy has tags %v, want nil", got.Tags)
		}
		tagged, err := store.Mutate(ctx, b, "ReadOnly", func(p *iam.Policy) error {
			p.Tags = map[string]string{"env": "prod", "owner": "platform"}
			return nil
		})
		if err != nil {
			t.Fatalf("tag previous-release policy: %v", err)
		}
		if wantTags := (map[string]string{"env": "prod", "owner": "platform"}); !reflect.DeepEqual(tagged.Tags, wantTags) {
			t.Fatalf("tagged policy tags = %v, want %v", tagged.Tags, wantTags)
		}
		list, err := store.List[iam.Policy](ctx, b)
		if err != nil {
			t.Fatalf("list policies after tag: %v", err)
		}
		if len(list) != 1 || !reflect.DeepEqual(list[0].Object.Tags, tagged.Tags) {
			t.Fatalf("listed policies after tag = %+v, want the tagged ReadOnly policy", list)
		}
	})

	t.Run("access keys", func(t *testing.T) {
		activeID, inactiveID, rootID := "AKIAFIXTUREKEYAAAABB", "AKIAFIXTUREKEYCCCCDD", "ASIAFIXTUREROOTAAAAB"
		active := iam.AccessKey{
			Meta: iam.Meta{UID: "55555555-5555-4555-8555-555555555555", Generation: 1, Updated: fixtureNow.Add(-time.Hour)},
			ID:   activeID, UserName: "alice", Status: iam.KeyActive, Created: fixtureNow.Add(-9 * 24 * time.Hour),
			LastUsed: fixtureNow.Add(-time.Hour), LastUsedService: "s3", LastUsedRegion: "us-east-1",
		}
		inactive := iam.AccessKey{
			Meta: iam.Meta{UID: "66666666-6666-4666-8666-666666666666", Generation: 2, Updated: fixtureNow.Add(-time.Hour)},
			ID:   inactiveID, UserName: "alice", Status: iam.KeyInactive, Created: fixtureNow.Add(-8 * 24 * time.Hour),
		}
		root := iam.AccessKey{
			Meta: iam.Meta{UID: "77777777-7777-4777-8777-777777777777", Generation: 1, Updated: fixtureNow.Add(-time.Hour)},
			ID:   rootID, Root: true, Status: iam.KeyActive, Created: fixtureNow.Add(-60 * 24 * time.Hour),
		}
		for _, tc := range []struct {
			want   iam.AccessKey
			secret string
		}{
			{active, "fixture-active-secret-not-real"},
			{inactive, "fixture-inactive-secret-not-real"},
			{root, "fixture-root-secret-not-real"},
		} {
			got := readAccessKey(t, b, tc.want.ID, tc.want)
			if got.Secret.KeyID != fixtureKEKID {
				t.Fatalf("key %s KEK id = %q, want %q", got.ID, got.Secret.KeyID, fixtureKEKID)
			}
			plain, err := keys.Open(got.Secret, string(iam.KindAccessKey)+"/"+got.ID)
			if err != nil {
				t.Fatalf("open key %s secret: %v", got.ID, err)
			}
			if string(plain) != tc.secret {
				t.Fatalf("key %s secret = %q, want %q", got.ID, plain, tc.secret)
			}
		}
	})

	t.Run("access key indexes", func(t *testing.T) {
		for _, id := range []string{"AKIAFIXTUREKEYAAAABB", "AKIAFIXTUREKEYCCCCDD", "ASIAFIXTUREROOTAAAAB"} {
			readRecord(t, raw, id, iam.KeyIndex{ID: id, Project: fixtureProject})
		}
	})

	t.Run("mfa device with lock", func(t *testing.T) {
		want := iam.MfaDevice{
			Meta: iam.Meta{UID: "88888888-8888-4888-8888-888888888888", Generation: 3, Updated: fixtureNow.Add(-time.Hour)},
			Name: "alice-device", Path: "/engineering/", EnableTime: fixtureNow.Add(-7 * 24 * time.Hour),
			UserName: "alice", Enabled: true, Created: fixtureNow.Add(-8 * 24 * time.Hour),
			LastStep: 58000000, LockedUntil: fixtureNow.Add(10 * time.Minute), LockedSince: fixtureNow.Add(-5 * time.Minute),
		}
		got := readMfaDevice(t, b, want.Name, want)
		if got.Seed.KeyID != fixtureKEKID {
			t.Fatalf("device KEK id = %q, want %q", got.Seed.KeyID, fixtureKEKID)
		}
		seed, err := keys.Open(got.Seed, string(iam.KindMfaDevice)+"/"+strings.ToLower(got.Name))
		if err != nil {
			t.Fatalf("open device seed: %v", err)
		}
		wantSeed := make([]byte, 20)
		for i := range wantSeed {
			wantSeed[i] = byte(i)
		}
		if !bytes.Equal(seed, wantSeed) {
			t.Fatalf("device seed = %v, want %v", seed, wantSeed)
		}
	})

	t.Run("console session", func(t *testing.T) {
		want := iam.Session{
			Hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Project: fixtureProject,
			UserName: "alice", MFA: true, AuthTime: fixtureNow.Add(-time.Hour), Expires: fixtureNow.Add(11 * time.Hour),
			SourceIP: "192.0.2.10",
		}
		readRecord(t, raw, want.Hash, want)
	})

	t.Run("operation", func(t *testing.T) {
		want := iam.Operation{
			ID: "op-0123456789abcdef", Project: fixtureProject, RequestID: "req-user-create",
			Fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Response:    []byte(`{"name":"projects/acme/operations/op-0123456789abcdef","done":true}`),
			Created:     fixtureNow.Add(-time.Hour),
		}
		readRecord(t, raw, want.ID, want)
	})

	t.Run("replay entry", func(t *testing.T) {
		want := iam.ReplayEntry{
			Hash:    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			Expires: fixtureNow.Add(10 * time.Minute),
		}
		readRecord(t, raw, want.Hash, want)
	})

	t.Run("attempt counter", func(t *testing.T) {
		want := iam.AttemptCounter{
			Hash:  "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			Scope: iam.AttemptUser, Failures: 5, WindowStart: fixtureNow.Add(-5 * time.Minute),
			LockedUntil: fixtureNow.Add(10 * time.Minute),
		}
		readRecord(t, raw, want.Hash, want)
	})
}

func fixtureCounts() map[iam.Kind]int {
	return map[iam.Kind]int{
		iam.KindUser:      1,
		iam.KindGroup:     1,
		iam.KindRole:      1,
		iam.KindPolicy:    1,
		iam.KindAccessKey: 3,
		iam.KindMfaDevice: 1,
		iam.KindKeyIndex:  3,
		iam.KindSession:   1,
		iam.KindOperation: 1,
		iam.KindReplay:    1,
		iam.KindAttempt:   1,
	}
}

func loadFixtureCRs(t *testing.T, c client.Client, namespace string) map[iam.Kind]int {
	t.Helper()
	entries, err := os.ReadDir(fixtureDir())
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	ctx := context.Background()
	counts := map[iam.Kind]int{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(fixtureDir(), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		u := &unstructured.Unstructured{}
		if err := json.Unmarshal(b, u); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if got, want := u.GetAPIVersion(), kubestore.Group+"/"+kubestore.Version; got != want {
			t.Fatalf("%s apiVersion = %q, want %q", e.Name(), got, want)
		}
		if u.GetName() == "" || u.GetAnnotations()[kubestore.Group+"/key"] == "" {
			t.Fatalf("%s has no metadata.name or key annotation", e.Name())
		}
		u.SetNamespace(namespace)
		if err := c.Create(ctx, u); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		counts[iam.Kind(u.GetKind())]++
	}
	return counts
}

func readRecord[T iam.Object](t *testing.T, b store.Backend, key string, want T) T {
	t.Helper()
	e, err := b.Get(context.Background(), want.Kind(), key)
	if err != nil {
		t.Fatalf("get %s %q: %v", want.Kind(), key, err)
	}
	if e.Key != key {
		t.Fatalf("%s logical key = %q, want %q", want.Kind(), e.Key, key)
	}
	got, err := store.Get[T](context.Background(), b, key)
	if err != nil {
		t.Fatalf("decode %s %q: %v", want.Kind(), key, err)
	}
	if !reflect.DeepEqual(got.Object, want) {
		t.Fatalf("%s %q decoded\n got: %#v\nwant: %#v", want.Kind(), key, got.Object, want)
	}
	return got.Object
}

// readAccessKey compares every field except the sealed secret, which the
// caller opens with the fixture KEK.
func readAccessKey(t *testing.T, b store.Backend, key string, want iam.AccessKey) iam.AccessKey {
	t.Helper()
	got, err := store.Get[iam.AccessKey](context.Background(), b, key)
	if err != nil {
		t.Fatalf("decode %s %q: %v", want.Kind(), key, err)
	}
	sealed := got.Object.Secret
	got.Object.Secret = iam.Sealed{}
	if !reflect.DeepEqual(got.Object, want) {
		t.Fatalf("%s %q decoded\n got: %#v\nwant: %#v", want.Kind(), key, got.Object, want)
	}
	got.Object.Secret = sealed
	return got.Object
}

// readMfaDevice compares every field except the sealed seed, which the
// caller opens with the fixture KEK.
func readMfaDevice(t *testing.T, b store.Backend, key string, want iam.MfaDevice) iam.MfaDevice {
	t.Helper()
	got, err := store.Get[iam.MfaDevice](context.Background(), b, key)
	if err != nil {
		t.Fatalf("decode %s %q: %v", want.Kind(), key, err)
	}
	sealed := got.Object.Seed
	got.Object.Seed = iam.Sealed{}
	if !reflect.DeepEqual(got.Object, want) {
		t.Fatalf("%s %q decoded\n got: %#v\nwant: %#v", want.Kind(), key, got.Object, want)
	}
	got.Object.Seed = sealed
	return got.Object
}
