package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/secret"
)

func TestResolveStore(t *testing.T) {
	kek := map[string]string{secret.EnvKEK: base64.StdEncoding.EncodeToString(make([]byte, 32)), secret.EnvKEKID: "k1"}
	with := func(extra map[string]string) func(string) string {
		m := map[string]string{}
		for k, v := range kek {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return envOf(m)
	}
	nsFile := filepath.Join(t.TempDir(), "namespace")
	if err := os.WriteFile(nsFile, []byte("vws-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	inPod := map[string]string{envServiceHost: "10.96.0.1"}
	podNS := func(ns string) map[string]string { return map[string]string{envServiceHost: "h", envPodNamespace: ns} }
	kubeArgs := []string{"-store", "kube"}
	podOnlyNS := map[string]string{envPodNamespace: "vws-env"}
	for _, tc := range []struct {
		name   string
		args   []string
		env    func(string) string
		nsFile string
		mode   string
		ns     string
	}{
		{"outside a pod without namespace is memory", nil, noEnv, missing, storeMemory, ""},
		{"explicit namespace is kube", []string{"-namespace", "vws"}, with(nil), missing, storeKube, "vws"},
		{"pod env namespace", nil, with(podNS("vws-env")), missing, storeKube, "vws-env"},
		{"service account namespace file", nil, with(inPod), nsFile, storeKube, "vws-from-file"},
		{"flag beats pod env", []string{"-namespace", "vws"}, with(podNS("other")), nsFile, storeKube, "vws"},
		{"explicit memory in a pod", []string{"-store", "memory"}, with(inPod), nsFile, storeMemory, ""},
		{"explicit kube outside a pod", kubeArgs, with(podOnlyNS), missing, storeKube, "vws-env"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseConfigNS(tc.args, io.Discard, tc.env, tc.nsFile)
			if err != nil || c.storeMode != tc.mode || c.namespace != tc.ns {
				t.Fatalf("got mode %q namespace %q err %v, want %q %q", c.storeMode, c.namespace, err, tc.mode, tc.ns)
			}
		})
	}
	for _, tc := range []struct {
		name, want string
		args       []string
		env        func(string) string
	}{
		{"in a pod with no namespace never falls back to memory", "needs a namespace", nil, with(inPod)},
		{"kube with no namespace", "needs a namespace", kubeArgs, with(nil)},
		{"memory with namespace", "conflicts", []string{"-store", "memory", "-namespace", "vws"}, with(nil)},
		{"unknown mode", "-store must be", []string{"-store", "etcd"}, with(nil)},
		{"hostile namespace", "not a Kubernetes namespace", []string{"-namespace", "../x"}, with(nil)},
		{"hostile pod namespace", "not a Kubernetes namespace", nil, with(podNS(strings.Repeat("a", 64)))},
		{"pod without KEK", "KEK", nil, envOf(map[string]string{envServiceHost: "h", envPodNamespace: "vws"})},
		{
			"bootstrap on memory", "bootstrap needs the kube store",
			[]string{"bootstrap", "-store", "memory"},
			with(map[string]string{envRootProject: "acme"}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfigNS(tc.args, io.Discard, tc.env, missing)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestWaitStore(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	errDown := errors.New("down")
	calls := 0
	flaky := func(ctx context.Context) error {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("store check without a deadline")
		}
		if calls < 3 {
			return errDown
		}
		return nil
	}
	if err := waitStore(t.Context(), log, flaky, 5, time.Millisecond); err != nil || calls != 3 {
		t.Fatalf("flaky store: %v after %d calls", err, calls)
	}
	calls = 0
	down := func(context.Context) error { calls++; return errDown }
	if err := waitStore(t.Context(), log, down, 3, time.Millisecond); !errors.Is(err, errDown) || calls != 3 {
		t.Fatalf("down store: %v after %d calls, want 3", err, calls)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitStore(ctx, log, down, 5, time.Hour); !errors.Is(err, context.Canceled) || !errors.Is(err, errDown) {
		t.Fatalf("canceled: %v", err)
	}
}
