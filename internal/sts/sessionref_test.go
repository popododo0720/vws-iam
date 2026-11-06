package sts_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/sts"
)

const denyAssume = `{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}}`

// sessions issues a role session and a user session of alice.
func (e env) sessions(t *testing.T) (role, user sts.Credentials) {
	t.Helper()
	ctx := context.Background()
	role, err := e.svc.AssumeRole(ctx, e.caller(t, "alice"), nil, adminARN, "ref1", 0, sts.SessionPolicies{}, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	user, err = e.svc.GetSessionToken(ctx, e.caller(t, "alice"), 0, goodMFA("alice"))
	if err != nil {
		t.Fatal(err)
	}
	return role, user
}

func (e env) mint(t *testing.T, c sts.Credentials) string {
	t.Helper()
	ref, err := e.svc.MintSessionRef(c.AccessKeyID, c.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestSessionRefChecksOut(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	role, user := e.sessions(t)

	rr, err := e.svc.CheckSessionRef(ctx, e.mint(t, role))
	if err != nil {
		t.Fatal(err)
	}
	if rr.Project != acct || rr.Principal.Kind != authz.Role || rr.Principal.Name != "admin" ||
		rr.Principal.ARN != "arn:vws:sts::"+acct+":assumed-role/admin/ref1" || rr.SessionName != "ref1" ||
		rr.RoleID != "4" || rr.UniqueID() != "4:ref1" || rr.MFA || rr.Expires.IsZero() {
		t.Fatalf("role ref = %+v", rr)
	}
	ur, err := e.svc.CheckSessionRef(ctx, e.mint(t, user))
	if err != nil {
		t.Fatal(err)
	}
	if ur.Principal.Kind != authz.User || ur.Principal.Name != "alice" || ur.Principal.ARN != "" ||
		!ur.Principal.SessionToken || !ur.Principal.SessionMFA || !ur.MFA || ur.UniqueID() != "1" {
		t.Fatalf("user ref = %+v", ur)
	}

	root, err := e.svc.GetSessionToken(ctx, sts.RootCaller(false, time.Time{}), 0, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	rt, err := e.svc.CheckSessionRef(ctx, e.mint(t, root))
	if err != nil {
		t.Fatal(err)
	}
	if rt.Principal.Kind != authz.Root || rt.UniqueID() != acct || rt.MFA {
		t.Fatalf("root ref = %+v", rt)
	}

	// Checking is stateless: the same reference is good again, and minting
	// again gives a reference that is just as good.
	ref := e.mint(t, role)
	for range 3 {
		if _, err := e.svc.CheckSessionRef(ctx, ref); err != nil {
			t.Fatalf("repeat: %v", err)
		}
	}
	if _, err := e.svc.CheckSessionRef(ctx, e.mint(t, role)); err != nil {
		t.Fatal(err)
	}
}

func TestSessionRefRefusedAfterRevokeWithSkewedClocks(t *testing.T) {
	for _, d := range skews {
		t.Run("revoker"+d.String(), func(t *testing.T) {
			e := setup(t)
			ctx := context.Background()
			revoker := sts.New(e.b, e.keys, e.az, acct, (&clock{t: e.clk.t.Add(d)}).now)
			// Sessions outlast the largest skew, or a replica ahead of the
			// issuer would see them expire rather than revoked.
			role, err := e.svc.AssumeRole(ctx, e.caller(t, "alice"), nil, adminARN, "skew", 6*time.Hour,
				sts.SessionPolicies{}, sts.MFA{})
			if err != nil {
				t.Fatal(err)
			}
			user, err := e.svc.GetSessionToken(ctx, e.caller(t, "alice"), 0, sts.MFA{})
			if err != nil {
				t.Fatal(err)
			}
			roleRef, userRef := e.mint(t, role), e.mint(t, user)

			if err := revoker.RevokeSessions(ctx, authz.Role, "admin"); err != nil {
				t.Fatal(err)
			}
			for _, svc := range []*sts.Service{e.svc, revoker} {
				if _, err := svc.CheckSessionRef(ctx, roleRef); !errors.Is(err, sts.ErrInvalidToken) {
					t.Fatalf("role ref after revoke: %v", err)
				}
				if _, err := svc.CheckSessionRef(ctx, userRef); err != nil {
					t.Fatalf("user ref after a role revoke: %v", err)
				}
			}
			if err := revoker.RevokeSessions(ctx, authz.User, "alice"); err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.CheckSessionRef(ctx, userRef); !errors.Is(err, sts.ErrInvalidToken) {
				t.Fatalf("user ref after revoke: %v", err)
			}

			// A reference minted from a session issued after the revoke is good.
			role2, err := e.svc.AssumeRole(ctx, e.caller(t, "alice"), nil, adminARN, "skew2", 6*time.Hour,
				sts.SessionPolicies{}, sts.MFA{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.CheckSessionRef(ctx, e.mint(t, role2)); err != nil {
				t.Fatalf("session after revoke: %v", err)
			}
		})
	}
}

// TestSessionRefMintedAfterRevokeIsRefused: the generation is the one the
// session was issued at, not the one read when the reference is minted.
func TestSessionRefMintedAfterRevokeIsRefused(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	role, _ := e.sessions(t)
	if err := e.svc.RevokeSessions(ctx, authz.Role, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CheckSessionRef(ctx, e.mint(t, role)); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("ref minted from a revoked session: %v", err)
	}
}

func TestSessionRefRefusedWhenPrincipalRecreated(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	role, user := e.sessions(t)
	roleRef, userRef := e.mint(t, role), e.mint(t, user)

	if err := store.Delete[iam.Role](ctx, e.b, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CheckSessionRef(ctx, roleRef); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("deleted role: %v", err)
	}
	put(t, e.b, iam.Role{Name: "admin", ID: "44", AssumeRolePolicy: denyAssume})
	if _, err := e.svc.CheckSessionRef(ctx, roleRef); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("recreated role: %v", err)
	}

	if err := store.Delete[iam.User](ctx, e.b, "alice", ""); err != nil {
		t.Fatal(err)
	}
	put(t, e.b, iam.User{Name: "alice", ID: "11"})
	if _, err := e.svc.CheckSessionRef(ctx, userRef); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("recreated user: %v", err)
	}
}

func TestSessionRefExpires(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	role, _ := e.sessions(t)
	ref := e.mint(t, role)
	e.clk.t = e.clk.t.Add(time.Hour - time.Second)
	if _, err := e.svc.CheckSessionRef(ctx, ref); err != nil {
		t.Fatalf("one second before expiry: %v", err)
	}
	e.clk.t = e.clk.t.Add(time.Second)
	if _, err := e.svc.CheckSessionRef(ctx, ref); !errors.Is(err, sts.ErrExpired) {
		t.Fatalf("at expiry: %v", err)
	}
	// An expired session gets no reference.
	if _, err := e.svc.MintSessionRef(role.AccessKeyID, role.SessionToken); !errors.Is(err, sts.ErrExpired) {
		t.Fatalf("mint from an expired session: %v", err)
	}
}

func TestSessionRefHostileInput(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	role, _ := e.sessions(t)
	ref := e.mint(t, role)
	i := strings.LastIndexByte(ref, '.')

	flip := []byte(ref)
	flip[len(flip)-2] ^= 1
	headFlip := []byte(ref)
	headFlip[i+1] = 'A'
	if ref[i+1] == 'A' {
		headFlip[i+1] = 'B'
	}
	cases := map[string]string{
		"empty":            "",
		"no dot":           strings.ReplaceAll(ref, ".", ""),
		"leading dot":      ref[i:],
		"empty ciphertext": ref[:i+1],
		"tampered tail":    string(flip),
		"tampered head":    string(headFlip),
		"truncated":        ref[:len(ref)-4],
		"extra dot":        ref + ".",
		"dot in body":      ref[:i] + "." + ref[i+1:i+5] + "." + ref[i+5:],
		"not base64":       ref[:i+1] + "!!!!",
		"padded":           ref + "=",
		"over length":      ref[:i+1] + strings.Repeat("A", 5000),
		"other kek id":     "kek-2." + ref[i+1:],
		"session token":    role.SessionToken,
		"secret":           role.Secret,
		"key id":           role.AccessKeyID,
	}
	for name, in := range cases {
		if _, err := e.svc.CheckSessionRef(ctx, in); !errors.Is(err, sts.ErrInvalidToken) {
			t.Errorf("%s: err = %v, want InvalidClientTokenId", name, err)
		}
	}

	// A reference is not a session token, even presented with its own key id.
	if _, err := e.svc.Validate(ctx, role.AccessKeyID, ref); !errors.Is(err, sts.ErrInvalidToken) {
		t.Errorf("reference as a token: %v", err)
	}
	// Minting needs a token that opens: a reference or a forged one does not.
	for name, tok := range map[string]string{"reference": ref, "empty": "", "garbage": "kek-1.AAAA"} {
		if _, err := e.svc.MintSessionRef(role.AccessKeyID, tok); !errors.Is(err, sts.ErrInvalidToken) {
			t.Errorf("mint from %s: %v", name, err)
		}
	}
	if _, err := e.svc.MintSessionRef("AKIAAAAAAAAAAAAAAAAA", role.SessionToken); !errors.Is(err, sts.ErrInvalidToken) {
		t.Errorf("mint with a long-term key id: %v", err)
	}
}

func TestSessionRefStaysInItsProject(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	role, _ := e.sessions(t)
	ref := e.mint(t, role)

	const acct2 = "111111111111"
	b2 := memstore.New()
	put(t, b2, iam.Role{Name: "admin", ID: "4", AssumeRolePolicy: denyAssume})
	other := sts.New(b2, e.keys, authz.New(b2, acct2, e.clk.now), acct2, e.clk.now)
	if _, err := other.CheckSessionRef(ctx, ref); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("reference of another project: %v", err)
	}
	if _, err := other.MintSessionRef(role.AccessKeyID, role.SessionToken); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("mint for a token of another project: %v", err)
	}
}

// TestSessionRefHoldsNoSecret opens the sealed bytes with the keyring: the
// plaintext names the session but holds neither its secret nor its token,
// and the sealed bytes open only under the reference's own context.
func TestSessionRefHoldsNoSecret(t *testing.T) {
	e := setup(t)
	role, user := e.sessions(t)
	for _, c := range []sts.Credentials{role, user} {
		ref := e.mint(t, c)
		kid, body, _ := strings.Cut(ref, ".")
		ct, err := base64.RawURLEncoding.DecodeString(body)
		if err != nil {
			t.Fatal(err)
		}
		sealed := iam.Sealed{KeyID: kid, Ciphertext: ct}
		plain, err := e.keys.Open(sealed, "sts/session-ref/"+acct)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{c.Secret, c.SessionToken, c.SessionToken[strings.IndexByte(c.SessionToken, '.')+1:]} {
			if strings.Contains(string(plain), secret) {
				t.Fatalf("reference plaintext holds %.6q...", secret)
			}
		}
		if strings.Contains(ref, c.Secret) {
			t.Fatal("reference holds the secret")
		}
		if _, err := e.keys.Open(sealed, "sts/session/"+c.AccessKeyID); err == nil {
			t.Fatal("a reference opened as a session token")
		}
		if _, err := e.keys.Open(sealed, "sts/session-ref/111111111111"); err == nil {
			t.Fatal("a reference opened for another project")
		}
	}
}

func TestSessionRefSurvivesRestartAndKEKRotation(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	role, _ := e.sessions(t)
	ref := e.mint(t, role)

	restarted := sts.New(e.b, e.keys, e.az, acct, e.clk.now)
	if _, err := restarted.CheckSessionRef(ctx, ref); err != nil {
		t.Fatalf("after restart: %v", err)
	}

	// kek-1 stays in the ring after a rotation, so references sealed under
	// it still open; without it they do not.
	k1, k2 := make([]byte, 32), make([]byte, 32)
	for _, k := range [][]byte{k1, k2} {
		if _, err := rand.Read(k); err != nil {
			t.Fatal(err)
		}
	}
	oldRing, err := secret.NewKeyring("kek-1", map[string][]byte{"kek-1": k1})
	if err != nil {
		t.Fatal(err)
	}
	both, err := secret.NewKeyring("kek-2", map[string][]byte{"kek-1": k1, "kek-2": k2})
	if err != nil {
		t.Fatal(err)
	}
	onlyNew, err := secret.NewKeyring("kek-2", map[string][]byte{"kek-2": k2})
	if err != nil {
		t.Fatal(err)
	}
	old := sts.New(e.b, oldRing, e.az, acct, e.clk.now)
	cred, err := old.AssumeRole(ctx, e.caller(t, "alice"), nil, adminARN, "rot", 0, sts.SessionPolicies{}, sts.MFA{})
	if err != nil {
		t.Fatal(err)
	}
	oldRef, err := old.MintSessionRef(cred.AccessKeyID, cred.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	rotated := sts.New(e.b, both, e.az, acct, e.clk.now)
	if _, err := rotated.CheckSessionRef(ctx, oldRef); err != nil {
		t.Fatalf("old KEK still in the ring: %v", err)
	}
	// A reference minted under the new active KEK is not readable by the old ring.
	newRef, err := rotated.MintSessionRef(cred.AccessKeyID, cred.SessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(newRef, "kek-2.") {
		t.Fatalf("new reference not sealed under the active KEK: %.12s", newRef)
	}
	if _, err := old.CheckSessionRef(ctx, newRef); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("unknown KEK: %v", err)
	}
	retired := sts.New(e.b, onlyNew, e.az, acct, e.clk.now)
	if _, err := retired.CheckSessionRef(ctx, oldRef); !errors.Is(err, sts.ErrInvalidToken) {
		t.Fatalf("retired KEK: %v", err)
	}
}

// flakyBackend fails every Get once fail is set.
type flakyBackend struct {
	store.Backend
	fail bool
}

func (f *flakyBackend) Get(ctx context.Context, kind iam.Kind, key string) (store.Entry, error) {
	if f.fail {
		return store.Entry{}, errors.New("store down")
	}
	return f.Backend.Get(ctx, kind, key)
}

// TestSessionRefStoreFailureIsNotARefusal: a store error is returned as an
// error (the caller fails closed), never as a valid session and never as an
// InvalidClientTokenId that would hide an outage as a revocation.
func TestSessionRefStoreFailureIsNotARefusal(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	role, _ := e.sessions(t)
	ref := e.mint(t, role)
	fb := &flakyBackend{Backend: e.b}
	svc := sts.New(fb, e.keys, e.az, acct, e.clk.now)
	if _, err := svc.CheckSessionRef(ctx, ref); err != nil {
		t.Fatal(err)
	}
	fb.fail = true
	_, err := svc.CheckSessionRef(ctx, ref)
	if err == nil || errors.Is(err, sts.ErrInvalidToken) || errors.Is(err, sts.ErrExpired) {
		t.Fatalf("store failure: %v", err)
	}
}
