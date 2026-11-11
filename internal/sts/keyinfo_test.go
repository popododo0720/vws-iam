package sts_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/sts"
)

const keyInfoAllow = `{"Version":"2012-10-17",
	"Statement":{"Effect":"Allow","Action":"sts:GetAccessKeyInfo","Resource":"*"}}`

// keyInfoEnv is two projects sharing one backend, as grpcapi lays them
// out: each project's objects in its scoped view, the key index unscoped.
type keyInfoEnv struct {
	root   store.Backend
	svc    *sts.Service
	keys   *secret.Keyring
	clk    *clock
	own    *accesskey.Service
	other  *accesskey.Service
	caller sts.Caller
}

// keyInfoSetup builds the projects on memstore; its svc has no key index.
func keyInfoSetup(t testing.TB) keyInfoEnv { return keyInfoSetupOn(t, memstore.New()) }

// keyInfoSetupOn is keyInfoSetup on root.
func keyInfoSetupOn(t testing.TB, root store.Backend) keyInfoEnv {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.NewChaCha8([32]byte{1}).Read(k); err != nil {
		t.Fatal(err)
	}
	keys, err := secret.NewKeyring("kek-1", map[string][]byte{"kek-1": k})
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)}
	b := store.Scoped(root, acct)
	ob := store.Scoped(root, "other")
	put(t, b, iam.User{Name: "auditor", ID: "10", InlinePolicies: map[string]string{
		"info": keyInfoAllow,
		"ip": `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Action":"sts:GetAccessKeyInfo","Resource":"*",
			"Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}}`,
	}})
	put(t, b, iam.User{Name: "nobody", ID: "11"})
	put(t, ob, iam.User{Name: "carol", ID: "12"})
	az := authz.New(b, acct, clk.now)
	e := keyInfoEnv{
		root: root, keys: keys, clk: clk,
		svc:   sts.New(b, keys, az, acct, clk.now),
		own:   accesskey.New(b, root, acct, keys, clk.now),
		other: accesskey.New(ob, root, "other", keys, clk.now),
	}
	e.caller = e.resolve(t, "auditor")
	return e
}

func (e keyInfoEnv) resolve(t testing.TB, user string) sts.Caller {
	t.Helper()
	cred, err := e.own.Create(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.svc.Resolve(context.Background(), sts.Credential{AccessKeyID: cred.AccessKeyID})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (e keyInfoEnv) key(t *testing.T, s *accesskey.Service, user string) string {
	t.Helper()
	cred, err := s.Create(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	return cred.AccessKeyID
}

// TestGetAccessKeyInfoAnswersAnyProject: the account of an existing key
// of the caller's or another project, active or inactive, and the same
// answer on a repeat and from a restarted service.
func TestGetAccessKeyInfoAnswersAnyProject(t *testing.T) {
	e := keyInfoSetup(t)
	svc := e.indexed()
	ctx := context.Background()
	own := e.key(t, e.own, "nobody")
	theirs := e.key(t, e.other, "carol")
	for id, want := range map[string]string{own: acct, theirs: "other"} {
		for range 2 {
			got, err := svc.GetAccessKeyInfo(ctx, e.caller, nil, id)
			if err != nil || got != want {
				t.Fatalf("GetAccessKeyInfo(%s) = %q, %v; want %q", id, got, err, want)
			}
		}
	}
	if err := e.other.SetStatus(ctx, "carol", theirs, iam.KeyInactive); err != nil {
		t.Fatal(err)
	}
	restarted := e.indexed()
	if got, err := restarted.GetAccessKeyInfo(ctx, e.caller, nil, theirs); err != nil || got != "other" {
		t.Fatalf("inactive key: %q, %v", got, err)
	}
}

// indexed returns a service that reads the key index.
func (e keyInfoEnv) indexed() *sts.Service {
	b := store.Scoped(e.root, acct)
	return sts.New(b, e.keys, authz.New(b, acct, e.clk.now), acct, e.clk.now, sts.WithKeyIndex(e.root))
}

// TestGetAccessKeyInfoNoSuchKey: an unknown, deleted, pending, orphaned
// (index entry without its key) or never issued temporary key id is
// InvalidClientTokenId, never an account.
func TestGetAccessKeyInfoNoSuchKey(t *testing.T) {
	e := keyInfoSetup(t)
	svc := e.indexed()
	ctx := context.Background()
	deleted := e.key(t, e.other, "carol")
	if err := e.other.Delete(ctx, "carol", deleted); err != nil {
		t.Fatal(err)
	}
	pending, _, err := e.other.CreatePending(ctx, "carol", "")
	if err != nil {
		t.Fatal(err)
	}
	orphan := "AKIA" + strings.Repeat("Q", 16)
	if _, err := store.Create(ctx, e.root, iam.KeyIndex{ID: orphan, Project: "other"}); err != nil {
		t.Fatal(err)
	}
	asia, err := accesskey.NewKeyID("ASIA")
	if err != nil {
		t.Fatal(err)
	}
	for name, id := range map[string]string{
		"unknown": "AKIA" + strings.Repeat("A", 16), "deleted": deleted, "pending": pending.AccessKeyID,
		"orphan": orphan, "temporary": asia, "not a key format": strings.Repeat("x_", 8),
	} {
		got, err := svc.GetAccessKeyInfo(ctx, e.caller, nil, id)
		if !errors.Is(err, sts.ErrNoSuchAccessKey) || got != "" {
			t.Errorf("%s: %q, %v; want ErrNoSuchAccessKey", name, got, err)
		}
	}
}

// TestGetAccessKeyInfoUnauthorized: without sts:GetAccessKeyInfo, or
// under an IP-conditioned Deny, the caller is AccessDenied whether or not
// the key exists, so it learns nothing about the key.
func TestGetAccessKeyInfoUnauthorized(t *testing.T) {
	e := keyInfoSetup(t)
	svc := e.indexed()
	ctx := context.Background()
	nobody := e.resolve(t, "nobody")
	known := e.key(t, e.other, "carol")
	for _, id := range []string{known, "AKIA" + strings.Repeat("B", 16)} {
		if got, err := svc.GetAccessKeyInfo(ctx, nobody, nil, id); !errors.Is(err, sts.ErrAccessDenied) || got != "" {
			t.Errorf("no permission, %s: %q, %v", id, got, err)
		}
		denyIP := map[string][]string{"aws:SourceIp": {"10.1.2.3"}}
		if got, err := svc.GetAccessKeyInfo(ctx, e.caller, denyIP, id); !errors.Is(err, sts.ErrAccessDenied) || got != "" {
			t.Errorf("denied address, %s: %q, %v", id, got, err)
		}
	}
	if _, err := svc.GetAccessKeyInfo(ctx, sts.Caller{}, nil, known); !errors.Is(err, sts.ErrAccessDenied) {
		t.Errorf("unresolved caller: %v", err)
	}
	allowIP := map[string][]string{"aws:SourceIp": {"192.0.2.1"}}
	if got, err := svc.GetAccessKeyInfo(ctx, e.caller, allowIP, known); err != nil || got != "other" {
		t.Errorf("allowed address: %q, %v", got, err)
	}
}

// TestGetAccessKeyInfoValidation: AccessKeyId must be 16 to 128
// characters of [\w]; anything else is ValidationError, checked first.
func TestGetAccessKeyInfoValidation(t *testing.T) {
	e := keyInfoSetup(t)
	svc := e.indexed()
	ctx := context.Background()
	for _, id := range []string{
		"", strings.Repeat("A", 15), strings.Repeat("A", 129), "AKIA-AAAAAAAAAAAAAAA", "AKIA AAAAAAAAAAAAAAA",
		"AKIAAAAAAAAAAAAAAAA\n", "AKIAÄAAAAAAAAAAAAAAA",
	} {
		if _, err := svc.GetAccessKeyInfo(ctx, e.caller, nil, id); !errors.Is(err, sts.ErrInvalidRequest) {
			t.Errorf("%q: %v; want ValidationError", id, err)
		}
	}
	for _, id := range []string{strings.Repeat("A", 16), strings.Repeat("z_9", 42) + "zz"} {
		if _, err := svc.GetAccessKeyInfo(ctx, e.caller, nil, id); !errors.Is(err, sts.ErrNoSuchAccessKey) {
			t.Errorf("%q (%d chars): %v; want it to pass validation", id, len(id), err)
		}
	}
}

// TestGetAccessKeyInfoWithoutIndexFailsClosed: a service built without
// the key index answers no account.
func TestGetAccessKeyInfoWithoutIndexFailsClosed(t *testing.T) {
	e := keyInfoSetup(t)
	id := e.key(t, e.own, "nobody")
	got, err := e.svc.GetAccessKeyInfo(context.Background(), e.caller, nil, id)
	if err == nil || got != "" || errors.Is(err, sts.ErrNoSuchAccessKey) {
		t.Fatalf("no index: %q, %v", got, err)
	}
}

// sessionKeys issues an AssumeRole and a GetSessionToken session in the
// caller's project through svc, which writes the key index.
func (e keyInfoEnv) sessionKeys(t testing.TB, svc *sts.Service) []sts.Credentials {
	t.Helper()
	ctx := context.Background()
	b := store.Scoped(e.root, acct)
	put(t, b, iam.User{Name: "deployer", ID: "13", InlinePolicies: map[string]string{"assume": assumeAny}})
	put(t, b, iam.Role{
		Name: "ops", ID: "14",
		AssumeRolePolicy: `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:vws:iam::` +
			acct + `:user/deployer"},"Action":"sts:AssumeRole"}}`,
	})
	c := e.resolve(t, "deployer")
	ar, err := svc.AssumeRole(ctx, c, nil, "arn:vws:iam::"+acct+":role/ops", "s1", 15*time.Minute,
		sts.SessionPolicies{}, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	st, err := svc.GetSessionToken(ctx, c, time.Hour, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	return []sts.Credentials{ar, st}
}

// TestGetAccessKeyInfoSessionKeys: the ASIA key id of an AssumeRole or
// GetSessionToken session is answered with its project, by a restarted
// service too, until the session expires (#188). The index entry holds
// only the key id, project and expiry, never the secret or token.
func TestGetAccessKeyInfoSessionKeys(t *testing.T) {
	testSessionKeys(t, keyInfoSetup(t))
}

func testSessionKeys(t *testing.T, e keyInfoEnv) {
	ctx := context.Background()
	svc := e.indexed()
	creds := e.sessionKeys(t, svc)
	for _, c := range creds {
		if !strings.HasPrefix(c.AccessKeyID, "ASIA") {
			t.Fatalf("session key id %s", c.AccessKeyID)
		}
		for _, s := range []*sts.Service{svc, e.indexed()} {
			if got, err := s.GetAccessKeyInfo(ctx, e.caller, nil, c.AccessKeyID); err != nil || got != acct {
				t.Fatalf("GetAccessKeyInfo(%s) = %q, %v; want %q", c.AccessKeyID, got, err, acct)
			}
		}
		x, err := store.Get[iam.KeyIndex](ctx, e.root, c.AccessKeyID)
		if err != nil {
			t.Fatal(err)
		}
		if want := (iam.KeyIndex{ID: c.AccessKeyID, Project: acct, Expires: c.Expiration}); x.Object != want {
			t.Fatalf("index entry %+v; want %+v", x.Object, want)
		}
		raw, err := e.root.Get(ctx, iam.KindKeyIndex, c.AccessKeyID)
		if err != nil {
			t.Fatal(err)
		}
		if s := string(raw.Spec); strings.Contains(s, c.Secret) || strings.Contains(s, c.SessionToken) {
			t.Fatalf("index entry holds session material: %s", s)
		}
	}
	// The AssumeRole session (15 minutes) has expired; the GetSessionToken
	// one (1 hour) has not.
	e.clk.t = e.clk.t.Add(15*time.Minute + time.Second)
	got, err := svc.GetAccessKeyInfo(ctx, e.caller, nil, creds[0].AccessKeyID)
	if !errors.Is(err, sts.ErrNoSuchAccessKey) {
		t.Fatalf("expired session: %q, %v; want ErrNoSuchAccessKey", got, err)
	}
	if got, err := svc.GetAccessKeyInfo(ctx, e.caller, nil, creds[1].AccessKeyID); err != nil || got != acct {
		t.Fatalf("live session: %q, %v", got, err)
	}
}

// failIndex fails every KeyIndex create with err.
type failIndex struct {
	store.Backend
	err   error
	tries int
}

func (f *failIndex) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	if kind == iam.KindKeyIndex {
		f.tries++
		return "", f.err
	}
	return f.Backend.Create(ctx, kind, key, spec)
}

// TestSessionKeyIndexFailureIssuesNothing: when the index entry cannot be
// written, no credentials are handed out; a key id that is taken is tried
// again with a fresh id, a bounded number of times.
func TestSessionKeyIndexFailureIssuesNothing(t *testing.T) {
	for name, cause := range map[string]error{"unavailable": store.ErrUnavailable, "taken": store.ErrExists} {
		t.Run(name, func(t *testing.T) {
			e := keyInfoSetup(t)
			ctx := context.Background()
			fi := &failIndex{Backend: e.root, err: cause}
			b := store.Scoped(e.root, acct)
			svc := sts.New(b, e.keys, authz.New(b, acct, e.clk.now), acct, e.clk.now, sts.WithKeyIndex(fi))
			got, err := svc.GetSessionToken(ctx, e.resolve(t, "nobody"), time.Hour, sts.MFA{})
			if !errors.Is(err, cause) || got != (sts.Credentials{}) {
				t.Fatalf("GetSessionToken = %+v, %v; want %v and no credentials", got, err, cause)
			}
			if want := map[string]int{"unavailable": 1, "taken": 3}[name]; fi.tries != want {
				t.Fatalf("%d index creates; want %d", fi.tries, want)
			}
		})
	}
}
