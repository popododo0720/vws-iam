package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func TestStartupErrorsNameTheStep(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	keys, err := keyring(config{})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		step string
		run  func() error
	}{
		{"load KEK keyring", func() error { _, err := keyring(config{kekDir: missing}); return err }},
		{"load KEK keyring", func() error { _, err := keyring(config{storeMode: storeEtcd, credDir: missing}); return err }},
		{"open store", func() error { _, _, err := openStore(config{storeMode: storeEtcd, credDir: missing}); return err }},
		{"bootstrap root key", func() error {
			_, err := bootstrapRoot(t.Context(), memstore.New(), keys, config{rootDir: missing})
			return err
		}},
		{"tls config", func() error { _, err := (tlsFiles{certFile: missing}).serverConfig(); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.step, func(t *testing.T) {
			err := tc.run()
			if err == nil || !strings.HasPrefix(err.Error(), tc.step+": ") {
				t.Fatalf("missing step %q: %v", tc.step, err)
			}
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("filesystem cause lost: %v", err)
			}
		})
	}
}

func TestStartupErrorsHideCredentialValues(t *testing.T) {
	material := strings.Repeat("synthetic-key-material", 3)
	encoded := base64.StdEncoding.EncodeToString([]byte(material))
	_, err := keyring(config{getenv: envOf(map[string]string{secret.EnvKEK: encoded, secret.EnvKEKID: "test"})})
	assertStartupSecretHidden(t, err, material, encoded)
	keys, err := keyring(config{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = bootstrapRoot(t.Context(), memstore.New(), keys, config{getenv: envOf(map[string]string{
		envRootProject: "acme", envRootKeyID: "AKIA", envRootSecret: material, envRootPassword: material,
	})})
	assertStartupSecretHidden(t, err, material)
	dir := t.TempDir()
	for _, name := range []string{"cert", "key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(material), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err = (tlsFiles{certFile: filepath.Join(dir, "cert"), keyFile: filepath.Join(dir, "key")}).serverConfig()
	assertStartupSecretHidden(t, err, material)
}

func assertStartupSecretHidden(t *testing.T, err error, values ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("malformed credentials unexpectedly accepted")
	}
	for _, value := range values {
		if strings.Contains(err.Error(), value) {
			t.Fatal("credential value appeared in a startup error")
		}
	}
}
