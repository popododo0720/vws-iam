package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// pageOnly is a paging store on which a full List fails the test.
type pageOnly struct {
	*memstore.Store
	t      *testing.T
	limits []int64
	err    error
}

func (p *pageOnly) List(context.Context, iam.Kind) ([]store.Entry, error) {
	p.t.Error("readiness listed the whole kind")
	return nil, nil
}

func (p *pageOnly) ListPage(
	ctx context.Context, kind iam.Kind, limit int64, cont string,
) ([]store.Entry, string, error) {
	p.limits = append(p.limits, limit)
	if p.err != nil {
		return nil, "", p.err
	}
	return p.Store.ListPage(ctx, kind, limit, cont)
}

// TestStoreReadyReadsOnePage: the readiness check, run on every probe,
// reads one key index entry, also through store.WithRetry, not the whole
// kind, which grows with every live STS session (#352).
func TestStoreReadyReadsOnePage(t *testing.T) {
	p := &pageOnly{Store: memstore.New(), t: t}
	ready := storeReady(store.WithRetry(p, 2, 0))
	for range 2 {
		if err := ready(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(p.limits, []int64{1, 1}) {
		t.Fatalf("ListPage limits = %v, want one page of 1 per probe", p.limits)
	}
	p.err = store.ErrUnavailable
	if err := ready(t.Context()); !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("unavailable store: %v, want ErrUnavailable", err)
	}
}

func TestStoreFlags(t *testing.T) {
	const credDir = "/run/credentials/vws-iam.service"
	creds := envOf(map[string]string{envCredentials: credDir})
	envKEK := envOf(map[string]string{
		envCredentials: credDir, secret.EnvKEK: base64.StdEncoding.EncodeToString(make([]byte, 32)), secret.EnvKEKID: "k1",
	})
	etcd := []string{"-etcd-endpoints", "https://10.0.0.1:2379, https://etcd-2.vws:2379"}
	c, err := parseConfig(etcd, io.Discard, creds)
	if err != nil || c.storeMode != storeEtcd || c.credDir != credDir || c.etcdPrefix != "/vws/iam" ||
		!slices.Equal(c.etcdEndpoints, []string{"https://10.0.0.1:2379", "https://etcd-2.vws:2379"}) {
		t.Fatalf("default etcd store: %+v %v", c, err)
	}
	c, err = parseConfig(append(etcd, "-etcd-prefix", "/iam/a-1"), io.Discard, creds)
	if err != nil || c.etcdPrefix != "/iam/a-1" {
		t.Fatalf("prefix: %+v %v", c, err)
	}
	if c, err := parseConfig([]string{"-store", "memory"}, io.Discard, noEnv); err != nil || c.storeMode != storeMemory {
		t.Fatalf("memory store: %+v %v", c, err)
	}
	endpoint := func(e string) []string { return []string{"-etcd-endpoints", e} }
	for _, tc := range []struct {
		name, want string
		args       []string
		env        func(string) string
	}{
		{"kube is gone", "-store must be etcd or memory", []string{"-store", "kube"}, creds},
		{"auto is gone", "-store must be etcd or memory", []string{"-store", "auto"}, creds},
		{"kubeconfig is gone", "-kubeconfig", append([]string{"-kubeconfig", "/k"}, etcd...), creds},
		{"namespace is gone", "-namespace", []string{"-store", "memory", "-namespace", "vws"}, noEnv},
		{"etcd without endpoints", "needs -etcd-endpoints", nil, creds},
		{"plaintext endpoint", "not an https", endpoint("http://10.0.0.1:2379"), creds},
		{"endpoint without scheme", "not an https", endpoint("10.0.0.1:2379"), creds},
		{"endpoint without port", "not an https", endpoint("https://10.0.0.1"), creds},
		{"endpoint with user info", "not an https", endpoint("https://u:p@10.0.0.1:2379"), creds},
		{"endpoint with path", "not an https", endpoint("https://10.0.0.1:2379/v3"), creds},
		{"empty endpoint in list", "not an https", endpoint("https://10.0.0.1:2379,"), creds},
		{"relative prefix", "-etcd-prefix", append(etcd, "-etcd-prefix", "vws"), creds},
		{"prefix with trailing slash", "-etcd-prefix", append(etcd, "-etcd-prefix", "/vws/"), creds},
		{"prefix with space", "-etcd-prefix", append(etcd, "-etcd-prefix", "/vws iam"), creds},
		{"no credentials directory", "$CREDENTIALS_DIRECTORY", etcd, noEnv},
		{"env KEK with etcd", "reads the KEK", etcd, envKEK},
		{"kek-dir with etcd", "reads the KEK", append(etcd, "-kek-dir", "/k"), creds},
		{"memory with endpoints", "conflicts", []string{"-store", "memory", "-etcd-endpoints", "https://h:1"}, noEnv},
		{
			"bootstrap on memory", "bootstrap needs -store=etcd",
			[]string{"bootstrap", "-store", "memory"},
			envOf(map[string]string{envRootProject: "acme"}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseConfig(tc.args, io.Discard, tc.env)
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
