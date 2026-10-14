package secret_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
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
