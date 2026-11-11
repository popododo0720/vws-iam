package secret_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/secret"
)

func key(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealOpenAndRotation(t *testing.T) {
	k1, k2 := key(t), key(t)
	old, err := secret.NewKeyring("kek-1", map[string][]byte{"kek-1": k1})
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	s, err := old.Seal(plain, "IamAccessKey/AKIA1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(s.Ciphertext, plain) || s.KeyID != "kek-1" {
		t.Fatalf("ciphertext leaks plaintext or wrong key id %q", s.KeyID)
	}
	rotated, err := secret.NewKeyring("kek-2", map[string][]byte{"kek-1": k1, "kek-2": k2})
	if err != nil {
		t.Fatal(err)
	}
	got, err := rotated.Open(s, "IamAccessKey/AKIA1")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("rotated keyring cannot open old value: %v", err)
	}
	if !rotated.NeedsRewrap(s) {
		t.Fatal("old value does not need rewrap")
	}
	s2, err := rotated.Seal(plain, "IamAccessKey/AKIA1")
	if err != nil || s2.KeyID != "kek-2" {
		t.Fatalf("new seal uses %q: %v", s2.KeyID, err)
	}
	if _, err := old.Open(s2, "IamAccessKey/AKIA1"); !errors.Is(err, secret.ErrUnknownKEK) {
		t.Fatalf("old keyring opened a kek-2 value: %v", err)
	}
}

func TestOpenRejectsTamperingAndMovedCiphertext(t *testing.T) {
	k, err := secret.NewKeyring("a", map[string][]byte{"a": key(t)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := k.Seal([]byte("x"), "owner-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Open(s, "owner-2"); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("moved ciphertext opened: %v", err)
	}
	s.Ciphertext[len(s.Ciphertext)-1] ^= 1
	if _, err := k.Open(s, "owner-1"); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("tampered ciphertext opened: %v", err)
	}
	s.Ciphertext = s.Ciphertext[:3]
	if _, err := k.Open(s, "owner-1"); !errors.Is(err, secret.ErrOpen) {
		t.Fatalf("short ciphertext: %v", err)
	}
}

func TestKeyringRejectsBadKEKs(t *testing.T) {
	if _, err := secret.NewKeyring("a", map[string][]byte{"a": make([]byte, 16)}); err == nil {
		t.Fatal("16-byte KEK accepted")
	}
	if _, err := secret.NewKeyring("b", map[string][]byte{"a": key(t)}); !errors.Is(err, secret.ErrUnknownKEK) {
		t.Fatalf("missing active: %v", err)
	}
}

func TestLoadDirNeverEchoesKeyMaterial(t *testing.T) {
	dir := t.TempDir()
	k := key(t)
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("kek-1", base64.StdEncoding.EncodeToString(k)+"\n")
	write("active", "kek-1\n")
	if _, err := secret.LoadDir(dir); err != nil {
		t.Fatal(err)
	}
	bad := "not-base64!!" + base64.StdEncoding.EncodeToString(k)
	write("kek-2", bad)
	_, err := secret.LoadDir(dir)
	if err == nil || strings.Contains(err.Error(), bad) {
		t.Fatalf("bad KEK error %v echoes key material", err)
	}
}

// TestLoadPrefixed reads a keyring from systemd credential files next to
// unrelated credentials, and names the missing file when one is absent.
func TestLoadPrefixed(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("etcd-ca.pem", "not a key")
	if _, err := secret.LoadPrefixed(dir, "kek_"); err == nil || !strings.Contains(err.Error(), "kek_active") {
		t.Fatalf("missing active file: %v", err)
	}
	write("kek_active", "k2\n")
	write("kek_k1", base64.StdEncoding.EncodeToString(key(t)))
	_, err := secret.LoadPrefixed(dir, "kek_")
	if !errors.Is(err, secret.ErrUnknownKEK) || !strings.Contains(err.Error(), "kek_k2") {
		t.Fatalf("missing active key file: %v", err)
	}
	write("kek_k2", base64.StdEncoding.EncodeToString(key(t)))
	k, err := secret.LoadPrefixed(dir, "kek_")
	if err != nil || k.Active() != "k2" {
		t.Fatalf("credential keyring: %v", err)
	}
}

func TestFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	if _, ok, err := secret.FromEnv(env(nil)); ok || err != nil {
		t.Fatalf("unset: %v %v", ok, err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	k, ok, err := secret.FromEnv(env(map[string]string{secret.EnvKEK: key, secret.EnvKEKID: "k2"}))
	if !ok || err != nil || k.Active() != "k2" {
		t.Fatalf("set: %v %v", ok, err)
	}
	for _, m := range []map[string]string{{secret.EnvKEK: key}, {secret.EnvKEKID: "k"}, {secret.EnvKEK: "%%", secret.EnvKEKID: "k"}, {secret.EnvKEK: "AAAA", secret.EnvKEKID: "k"}} {
		if _, _, err := secret.FromEnv(env(m)); err == nil || strings.Contains(err.Error(), key) {
			t.Fatalf("%v accepted or leaked: %v", m, err)
		}
	}
}

// TestDigests covers the keyed store digests (#41): stable, separated by
// purpose and KEK, never the plain SHA-256 of the input, in KEK id order,
// and a KEK's digest is the same in every ring that holds it.
func TestDigests(t *testing.T) {
	ka, kb := key(t), key(t)
	ring := func(active string, ids ...string) *secret.Keyring {
		t.Helper()
		keys := map[string][]byte{}
		for _, id := range ids {
			keys[id] = map[string][]byte{"a": ka, "b": kb}[id]
		}
		k, err := secret.NewKeyring(active, keys)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	a, ab, ba := ring("a", "a"), ring("a", "a", "b"), ring("b", "b", "a")
	const msg = "user\nacme/alice"
	d := a.Digests("attempt", msg)
	if len(d) != 1 || len(d[0]) != 64 {
		t.Fatalf("digests %q, want one hex SHA-256", d)
	}
	if again := a.Digests("attempt", msg); !slices.Equal(again, d) {
		t.Fatalf("not deterministic: %q then %q", d, again)
	}
	if other := a.Digests("replay", msg); other[0] == d[0] {
		t.Fatal("purposes share a digest")
	}
	plain := sha256.Sum256([]byte(msg))
	plainPurpose := sha256.Sum256([]byte("attempt\x00" + msg))
	if d[0] == hex.EncodeToString(plain[:]) || d[0] == hex.EncodeToString(plainPurpose[:]) {
		t.Fatal("digest is the plain SHA-256 of its input")
	}
	got := ab.Digests("attempt", msg)
	if len(got) != 2 || got[0] != d[0] || got[1] == d[0] {
		t.Fatalf("ring {a,b} = %q, want a's digest %q first and b's apart", got, d[0])
	}
	if rev := ba.Digests("attempt", msg); !slices.Equal(rev, got) {
		t.Fatalf("order depends on the active KEK: %q vs %q", rev, got)
	}
	if b := ring("b", "b").Digests("attempt", msg); b[0] != got[1] {
		t.Fatalf("b's digest %q differs in ring {a,b}: %q", b[0], got[1])
	}
}

// TestDigestsDuplicateKEK: KEK ids that hold the same bytes give one
// digest, so a replay claim does not meet its own entry and an attempt is
// counted once.
func TestDigestsDuplicateKEK(t *testing.T) {
	ka, kb := key(t), key(t)
	k, err := secret.NewKeyring("a", map[string][]byte{"a": ka, "b": kb, "c": ka})
	if err != nil {
		t.Fatal(err)
	}
	if d := k.Digests("replay", "m"); len(d) != 2 || d[0] == d[1] {
		t.Fatalf("digests %q, want one per distinct KEK", d)
	}
}
