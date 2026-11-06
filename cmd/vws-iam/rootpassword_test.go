package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/password"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func rootKey(t *testing.T) (id, sec string) {
	t.Helper()
	sec, err := accesskey.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	if id, err = accesskey.NewKeyID("AKIA"); err != nil {
		t.Fatal(err)
	}
	return id, sec
}

func rootHash(t *testing.T, b store.Backend) store.Versioned[iam.RootLogin] {
	t.Helper()
	r, err := store.Get[iam.RootLogin](t.Context(), store.Scoped(b, "acme"), iam.RootLoginKey)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestBootstrapRootPassword: bootstrap sets the optional root console
// password (#34) from the env or the mounted Secret's password file (only
// its line ending removed), rerunning it writes nothing, a bad password
// fails without echoing it, and no password leaves no root login.
func TestBootstrapRootPassword(t *testing.T) {
	keys, err := keyring(config{})
	if err != nil {
		t.Fatal(err)
	}
	id, sec := rootKey(t)
	ctx := t.Context()

	b := memstore.New()
	env := map[string]string{envRootProject: "acme", envRootKeyID: id, envRootSecret: sec}
	if _, err := bootstrapRoot(ctx, b, keys, config{getenv: envOf(env)}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get[iam.RootLogin](ctx, store.Scoped(b, "acme"), iam.RootLoginKey); err == nil {
		t.Fatal("a root login without a password")
	}
	env[envRootPassword] = " Root-Console-9 "
	if _, err := bootstrapRoot(ctx, b, keys, config{getenv: envOf(env)}); err != nil {
		t.Fatal(err)
	}
	first := rootHash(t, b)
	if password.Verify(" Root-Console-9 ", first.Object.PasswordHash) != nil {
		t.Fatal("env password not stored as given")
	}
	if _, err := bootstrapRoot(ctx, b, keys, config{getenv: envOf(env)}); err != nil ||
		rootHash(t, b).Version != first.Version {
		t.Fatalf("rerun wrote the root login: %v", err)
	}
	env[envRootPassword] = "weakpass"
	if _, err := bootstrapRoot(ctx, b, keys, config{getenv: envOf(env)}); err == nil ||
		strings.Contains(err.Error(), "weakpass") {
		t.Fatalf("weak password: %v", err)
	}

	dir := t.TempDir()
	b = memstore.New()
	files := map[string]string{
		"project": "acme\n", "access_key_id": id, "secret_access_key": sec, "password": "Root-Console-9\r\n",
	}
	for n, v := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := bootstrapRoot(ctx, b, keys, config{rootDir: dir}); err != nil {
		t.Fatal(err)
	}
	if password.Verify("Root-Console-9", rootHash(t, b).Object.PasswordHash) != nil {
		t.Fatal("password file not stored without its line ending")
	}
}
