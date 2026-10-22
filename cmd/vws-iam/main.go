// Command vws-iam serves VWS identity and access management over gRPC.
//
// All state (users, groups, roles, policies, access keys, MFA devices, STS
// revocations, replay entries, attempt counters, and operations) persists
// as iam.vws.popododo0720.io custom resources in one namespace, so every
// replica reads the same state and a restart loses nothing. -store picks the
// backend: kube, memory, or auto (kube with -namespace or inside a pod,
// memory only outside Kubernetes).
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/popododo0720/vws-lib/obs"
	"github.com/popododo0720/vws-lib/obs/health"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

type config struct {
	listen, namespace, kubeconfig, kekDir, rootDir, healthAddr string
	// storeMode is the resolved backend: storeKube or storeMemory.
	storeMode string
	// nsFile is the service account namespace file (tests replace it).
	nsFile string
	// bootstrap is the one-shot mode: import the root key and exit.
	bootstrap bool
	getenv    func(string) string
}

// Store modes of -store.
const (
	storeAuto   = "auto"
	storeKube   = "kube"
	storeMemory = "memory"
)

// Pod environment used to find the namespace when -namespace is unset.
// Kubernetes sets envServiceHost in every container; envPodNamespace comes
// from the downward API; saNamespaceFile is mounted with the service
// account token.
const (
	envServiceHost  = "KUBERNETES_SERVICE_HOST"
	envPodNamespace = "POD_NAMESPACE"
	saNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// namespaceRE is a Kubernetes namespace name (DNS-1123 label).
var namespaceRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Root credential environment of the bootstrap Job (secretKeyRef).
const (
	envRootProject = "VWS_IAM_ROOT_PROJECT"
	envRootKeyID   = "VWS_IAM_ROOT_ACCESS_KEY_ID"
	envRootSecret  = "VWS_IAM_ROOT_SECRET_ACCESS_KEY"
)

const usage = `usage: vws-iam [flags]            serve gRPC
       vws-iam bootstrap [flags]  import the root key once and exit (idempotent; helm post-install Job)

KEK: env VWS_IAM_KEK (base64 of 32 bytes) + VWS_IAM_KEK_ID, or -kek-dir.
Bootstrap root credentials: env VWS_IAM_ROOT_PROJECT, VWS_IAM_ROOT_ACCESS_KEY_ID,
VWS_IAM_ROOT_SECRET_ACCESS_KEY, or -root-credentials-dir.
`

func parseConfig(args []string, stderr io.Writer, getenv func(string) string) (config, error) {
	return parseConfigNS(args, stderr, getenv, saNamespaceFile)
}

// parseConfigNS is parseConfig reading the pod namespace from nsFile.
func parseConfigNS(args []string, stderr io.Writer, getenv func(string) string, nsFile string) (config, error) {
	c := config{getenv: getenv, nsFile: nsFile}
	if len(args) > 0 && args[0] == "bootstrap" {
		c.bootstrap, args = true, args[1:]
	}
	fs := flag.NewFlagSet("vws-iam", flag.ContinueOnError)
	fs.Usage = func() {
		if _, err := io.WriteString(stderr, usage); err == nil {
			fs.PrintDefaults()
		}
	}
	fs.SetOutput(stderr)
	fs.StringVar(&c.listen, "listen", "127.0.0.1:9095", "gRPC listen address")
	fs.StringVar(&c.storeMode, "store", storeAuto,
		"backend: kube (custom resources, shared by every replica), memory (one process, lost on exit; "+
			"never with replicas), or auto (kube with -namespace or inside a pod, else memory)")
	fs.StringVar(&c.namespace, "namespace", "",
		"Kubernetes namespace of the IAM custom resources; empty uses the pod namespace "+
			"(env POD_NAMESPACE, then the service account namespace file)")
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "kubeconfig path; empty uses in-cluster config")
	fs.StringVar(&c.kekDir, "kek-dir", "", "directory of the mounted vws-iam-kek Secret: one base64 32-byte key per id and an \"active\" file")
	fs.StringVar(&c.rootDir, "root-credentials-dir", "", "optional mounted Secret with project, access_key_id and secret_access_key files: imported once as that project's root key")
	fs.StringVar(&c.healthAddr, "health-listen", "127.0.0.1:9096", "HTTP address of /healthz and /readyz; empty disables")
	if err := fs.Parse(args); err != nil {
		return c, fmt.Errorf("flags: %w", err)
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	if err := c.resolveStore(); err != nil {
		return c, err
	}
	hasEnvKEK := getenv(secret.EnvKEK) != "" || getenv(secret.EnvKEKID) != ""
	switch {
	case hasEnvKEK && c.kekDir != "":
		return c, errors.New("set either VWS_IAM_KEK/VWS_IAM_KEK_ID or -kek-dir, not both")
	case !hasEnvKEK && c.kekDir == "" && (c.storeMode == storeKube || c.bootstrap):
		return c, errors.New("a KEK (VWS_IAM_KEK + VWS_IAM_KEK_ID, or -kek-dir) is required with the kube " +
			"store or bootstrap: an ephemeral KEK would make stored secrets unreadable")
	case c.bootstrap && c.storeMode != storeKube:
		return c, errors.New("bootstrap needs the kube store (-namespace, or run in a pod)")
	case c.bootstrap && c.rootDir == "" && getenv(envRootProject) == "":
		return c, errors.New("bootstrap needs root credentials (VWS_IAM_ROOT_* env or -root-credentials-dir)")
	}
	return c, nil
}

// resolveStore turns -store and -namespace into storeKube with a
// namespace, or storeMemory. Inside a pod, auto never falls back to
// memory: replicas with private memory would diverge and lose state on
// restart (#110), so an unknown namespace is an error instead.
func (c *config) resolveStore() error {
	switch c.storeMode {
	case storeMemory:
		if c.namespace != "" {
			return errors.New("-store=memory conflicts with -namespace")
		}
		return nil
	case storeAuto:
		if c.namespace == "" && c.getenv(envServiceHost) == "" {
			c.storeMode = storeMemory
			return nil
		}
	case storeKube:
	default:
		return fmt.Errorf("-store must be %s, %s or %s, not %q", storeAuto, storeKube, storeMemory, c.storeMode)
	}
	c.storeMode = storeKube
	if c.namespace == "" {
		ns, err := podNamespace(c.getenv, c.nsFile)
		if err != nil {
			return err
		}
		c.namespace = ns
	}
	if !namespaceRE.MatchString(c.namespace) {
		return fmt.Errorf("namespace %q is not a Kubernetes namespace name", c.namespace)
	}
	return nil
}

// podNamespace is env POD_NAMESPACE, else the service account namespace
// file.
func podNamespace(getenv func(string) string, nsFile string) (string, error) {
	if ns := strings.TrimSpace(getenv(envPodNamespace)); ns != "" {
		return ns, nil
	}
	b, err := os.ReadFile(nsFile) //nolint:gosec // fixed service account path; tests pass a temp file
	if err != nil {
		return "", fmt.Errorf("kube store needs a namespace: pass -namespace, set %s, or mount the "+
			"service account (%w); -store=memory keeps state in one process only", envPodNamespace, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func main() {
	cfg, err := parseConfig(os.Args[1:], os.Stderr, os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vws-iam:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.bootstrap {
		if err := runBootstrap(ctx, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "vws-iam bootstrap:", err)
			stop()
			os.Exit(1)
		}
		return
	}
	if err := run(ctx, cfg); err != nil {
		slog.Default().LogAttrs(ctx, slog.LevelError, "vws-iam stopped", slog.String(obs.FieldErr, err.Error()))
		stop()
		os.Exit(1)
	}
}

func openStore(cfg config) (store.Backend, error) {
	if cfg.storeMode == storeMemory {
		return memstore.New(), nil
	}
	s, err := kubestore.Open(cfg.kubeconfig, cfg.namespace)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	return store.WithRetry(s, 4, 100*time.Millisecond), nil
}

// keyring loads the KEK keyring; memory mode may use a random one.
func keyring(cfg config) (*secret.Keyring, error) {
	if cfg.getenv != nil {
		k, ok, err := secret.FromEnv(cfg.getenv)
		if err != nil {
			return nil, fmt.Errorf("load KEK: %w", err)
		}
		if ok {
			return k, nil
		}
	}
	if cfg.kekDir != "" {
		k, err := secret.LoadDir(cfg.kekDir)
		if err != nil {
			return nil, fmt.Errorf("load KEK: %w", err)
		}
		return k, nil
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return nil, fmt.Errorf("ephemeral KEK: %w", err)
	}
	k, err := secret.NewKeyring("ephemeral", map[string][]byte{"ephemeral": kek})
	if err != nil {
		return nil, fmt.Errorf("ephemeral KEK: %w", err)
	}
	return k, nil
}

func readTrim(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // operator-supplied mount path
	if err != nil {
		return "", fmt.Errorf("root credentials: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// bootstrapRoot imports the root key once. Nothing secret is logged.
func bootstrapRoot(ctx context.Context, b store.Backend, keys *secret.Keyring, cfg config) (string, error) {
	var project, id, sec string
	if cfg.rootDir != "" {
		var err error
		if project, err = readTrim(cfg.rootDir, "project"); err != nil {
			return "", err
		}
		if id, err = readTrim(cfg.rootDir, "access_key_id"); err != nil {
			return "", err
		}
		if sec, err = readTrim(cfg.rootDir, "secret_access_key"); err != nil {
			return "", err
		}
	} else {
		project, id, sec = strings.TrimSpace(cfg.getenv(envRootProject)), strings.TrimSpace(cfg.getenv(envRootKeyID)), strings.TrimSpace(cfg.getenv(envRootSecret))
	}
	if !iam.ValidProject(project) || !strings.HasPrefix(id, "AKIA") || len(sec) < 32 {
		return "", errors.New("root credentials: invalid project, access key id or secret")
	}
	svc := accesskey.New(store.Scoped(b, project), b, project, keys, nil)
	if _, err := svc.Import(ctx, "", id, sec, true); err != nil && !errors.Is(err, store.ErrExists) {
		return "", fmt.Errorf("root credentials: %w", err)
	}
	return project, nil
}

func run(ctx context.Context, cfg config) (err error) {
	shutdown, err := obs.Setup(ctx, obs.ForService(grpcapi.ServiceName), withVersion())
	if err != nil {
		return fmt.Errorf("obs setup: %w", err)
	}
	defer func() {
		if serr := shutdown(context.WithoutCancel(ctx)); serr != nil {
			err = errors.Join(err, fmt.Errorf("obs shutdown: %w", serr))
		}
	}()
	log := slog.Default()
	keys, err := keyring(cfg)
	if err != nil {
		return err
	}
	log.LogAttrs(ctx, slog.LevelInfo, "loaded KEK keyring", slog.String("active_kek", keys.Active()))
	backend, err := openStore(cfg)
	if err != nil {
		return err
	}
	if cfg.storeMode == storeMemory {
		log.LogAttrs(ctx, slog.LevelWarn, "state is in memory: not shared between replicas and lost on exit",
			slog.String("store", cfg.storeMode))
	}
	ready := func(ctx context.Context) error {
		_, err := backend.List(ctx, iam.KindKeyIndex)
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		return nil
	}
	if err := waitStore(ctx, log, ready, storeWaitAttempts, time.Second); err != nil {
		return err
	}
	if cfg.rootDir != "" {
		project, err := bootstrapRoot(ctx, backend, keys, cfg)
		if err != nil {
			return err
		}
		log.LogAttrs(ctx, slog.LevelInfo, "root credential ready", slog.String("project", project))
	}
	health.Default().Register("store", ready)
	if cfg.healthAddr != "" {
		bound, stopHealth, err := health.Serve(ctx, cfg.healthAddr, health.Default())
		if err != nil {
			return fmt.Errorf("health: %w", err)
		}
		defer func() { err = errors.Join(err, stopHealth(context.WithoutCancel(ctx))) }()
		log.LogAttrs(ctx, slog.LevelInfo, "health serving", slog.String("addr", bound))
	}

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := grpc.NewServer(grpcapi.ServerOptions()...)
	api := grpcapi.New(backend, keys)
	grpcapi.Register(srv, api)
	go collectReplays(ctx, log, api)
	hs := grpchealth.NewServer()
	healthpb.RegisterHealthServer(srv, hs)
	go watchHealth(ctx, hs, ready)
	go func() {
		<-ctx.Done()
		health.Default().NotReady()
		hs.Shutdown()
		srv.GracefulStop()
	}()
	log.LogAttrs(ctx, slog.LevelInfo, "serving", slog.String("addr", lis.Addr().String()),
		slog.String("store", cfg.storeMode), slog.String("namespace", cfg.namespace))
	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// storeWaitAttempts bounds the startup store check: with a 1 s base the
// waits are 1, 2, 4, 8, 16 s, so about 30 s before giving up.
const storeWaitAttempts = 6

// waitStore checks the store before serving, retrying with exponential
// backoff, each try under its own deadline. A missing CRD, Role or
// namespace fails startup, so a rollout stops on the old pods instead of
// serving errors.
func waitStore(
	ctx context.Context, log *slog.Logger, ready func(context.Context) error, attempts int, base time.Duration,
) error {
	wait := base
	for i := 1; ; i++ {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := ready(cctx)
		cancel()
		if err == nil {
			return nil
		}
		if i >= attempts {
			return fmt.Errorf("store not ready after %d attempts: %w", attempts, err)
		}
		log.LogAttrs(ctx, slog.LevelWarn, "store not ready", slog.Int("attempt", i), slog.String(obs.FieldErr, err.Error()))
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("store not ready: %w", errors.Join(err, ctx.Err()))
		case <-t.C:
		}
		wait *= 2
	}
}

// watchHealth mirrors the store readiness into the gRPC health service.
func watchHealth(ctx context.Context, hs *grpchealth.Server, ready func(context.Context) error) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		st := healthpb.HealthCheckResponse_SERVING
		if ready(cctx) != nil {
			st = healthpb.HealthCheckResponse_NOT_SERVING
		}
		cancel()
		hs.SetServingStatus("", st)
		hs.SetServingStatus(grpcapi.ServiceName, st)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// collectReplays deletes expired SigV4 replay entries (#33) and attempt
// counters whose window and lockout are over (#12) every few minutes. Each replica runs it; races between them are harmless.
func collectReplays(ctx context.Context, log *slog.Logger, api *grpcapi.Server) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, gc := range []struct {
			name string
			run  func(context.Context) (int, error)
		}{{"replay", api.GCReplayEntries}, {"attempt", api.GCAttemptCounters}} {
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			n, err := gc.run(cctx)
			cancel()
			if err != nil {
				log.LogAttrs(ctx, slog.LevelWarn, "gc failed", slog.String("gc", gc.name), slog.String("error", err.Error()))
				continue
			}
			log.LogAttrs(ctx, slog.LevelDebug, "gc done", slog.String("gc", gc.name), slog.Int("deleted", n))
		}
	}
}

// runBootstrap is the one-shot Job: open the store, import the root key
// (a no-op when it exists) and exit. It logs the project only.
func runBootstrap(ctx context.Context, cfg config) error {
	keys, err := keyring(cfg)
	if err != nil {
		return err
	}
	backend, err := openStore(cfg)
	if err != nil {
		return err
	}
	project, err := bootstrapRoot(ctx, backend, keys, cfg)
	if err != nil {
		return err
	}
	slog.Default().LogAttrs(ctx, slog.LevelInfo, "bootstrap done", slog.String("project", project))
	return nil
}
