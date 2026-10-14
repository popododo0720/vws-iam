package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

func TestParseConfig(t *testing.T) {
	c, err := parseConfig([]string{"-namespace", "vws-iam", "-kek-dir", "/k", "-listen", ":1"}, io.Discard, noEnv)
	if err != nil || c.namespace != "vws-iam" || c.listen != ":1" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := parseConfig([]string{"-namespace", "vws-iam"}, io.Discard, noEnv); err == nil {
		t.Fatal("persistent store without a KEK accepted")
	}
	if _, err := parseConfig([]string{"extra"}, io.Discard, noEnv); err == nil {
		t.Fatal("extra argument accepted")
	}
	if _, err := parseConfig([]string{"-h"}, io.Discard, noEnv); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h: %v", err)
	}
}

func noEnv(string) string { return "" }

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestParseConfigEnvAndBootstrap(t *testing.T) {
	kek := map[string]string{secret.EnvKEK: base64.StdEncoding.EncodeToString(make([]byte, 32)), secret.EnvKEKID: "k1"}
	if _, err := parseConfig([]string{"-namespace", "ns"}, io.Discard, envOf(kek)); err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig([]string{"-namespace", "ns", "-kek-dir", "/k"}, io.Discard, envOf(kek)); err == nil {
		t.Fatal("env and dir KEK both accepted")
	}
	if _, err := parseConfig([]string{"bootstrap", "-namespace", "ns"}, io.Discard, envOf(kek)); err == nil {
		t.Fatal("bootstrap without root credentials accepted")
	}
	kek[envRootProject] = "acme"
	c, err := parseConfig([]string{"bootstrap", "-namespace", "ns"}, io.Discard, envOf(kek))
	if err != nil || !c.bootstrap {
		t.Fatalf("%+v %v", c, err)
	}
	k, err := keyring(c)
	if err != nil || k.Active() != "k1" {
		t.Fatalf("env KEK: %v", err)
	}
}

func TestBootstrapRootFromEnv(t *testing.T) {
	sec, err := accesskey.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	id, err := accesskey.NewKeyID("AKIA")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config{getenv: envOf(map[string]string{envRootProject: "acme", envRootKeyID: id, envRootSecret: sec})}
	keys, err := keyring(config{})
	if err != nil {
		t.Fatal(err)
	}
	b := memstore.New()
	for range 2 {
		if p, err := bootstrapRoot(t.Context(), b, keys, cfg); err != nil || p != "acme" {
			t.Fatalf("%q %v", p, err)
		}
	}
	cfg.getenv = envOf(map[string]string{envRootProject: "acme", envRootKeyID: id, envRootSecret: "short"})
	if _, err := bootstrapRoot(t.Context(), b, keys, cfg); err == nil || strings.Contains(err.Error(), "short") {
		t.Fatalf("weak secret: %v", err)
	}
}

func TestBootstrapRoot(t *testing.T) {
	dir := t.TempDir()
	sec, err := accesskey.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	id, err := accesskey.NewKeyID("AKIA")
	if err != nil {
		t.Fatal(err)
	}
	for n, v := range map[string]string{"project": "acme\n", "access_key_id": id, "secret_access_key": sec} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := keyring(config{})
	if err != nil {
		t.Fatal(err)
	}
	b := memstore.New()
	ctx := context.Background()
	for range 2 { // idempotent across restarts
		if p, err := bootstrapRoot(ctx, b, keys, config{rootDir: dir}); err != nil || p != "acme" {
			t.Fatalf("%q %v", p, err)
		}
	}
	svc := accesskey.New(store.Scoped(b, "acme"), b, "acme", keys, nil)
	cred, err := svc.GetSigningCredential(ctx, id)
	if err != nil || !cred.Root || cred.Secret != sec {
		t.Fatalf("root key not usable: %v root=%v", err, cred.Root)
	}
	if _, err := secret.NewKeyring("x", nil); err == nil {
		t.Fatal("empty keyring accepted")
	}
}
