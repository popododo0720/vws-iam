// Command vws-iam serves VWS identity and access management over gRPC.
//
// All state (users, groups, roles, policies, access keys, MFA devices, STS
// revocations, replay entries, attempt counters, and operations) persists
// in etcd under one key prefix, so every replica reads the same state and a
// restart loses nothing. -store picks the backend: etcd (default) or
// memory (one process only).
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
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/popododo0720/vws-lib/obs"
	"github.com/popododo0720/vws-lib/obs/health"

	"github.com/popododo0720/vws-iam/internal/accesskey"
	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
	"github.com/popododo0720/vws-iam/internal/sts"
)

type config struct {
	listen, kekDir, rootDir, healthAddr string
	// storeMode is storeEtcd or storeMemory.
	storeMode     string
	etcdEndpoints []string
	etcdPrefix    string
	// credDir is $CREDENTIALS_DIRECTORY, set with storeEtcd.
	credDir string
	// bootstrap is the one-shot mode: import the root key and exit.
	bootstrap bool
	tls       tlsFiles
	// insecurePlaintext allows serving without TLS on a non-loopback address.
	insecurePlaintext bool
	// saml is the AssumeRoleWithSAML service provider; zero refuses it.
	saml   sts.SAMLServiceProvider
	getenv func(string) string
}

// Store modes of -store.
const (
	storeEtcd   = "etcd"
	storeMemory = "memory"
)

// Root credential environment of the bootstrap Job (secretKeyRef).
const (
	envRootProject = "VWS_IAM_ROOT_PROJECT"
	envRootKeyID   = "VWS_IAM_ROOT_ACCESS_KEY_ID"
	envRootSecret  = "VWS_IAM_ROOT_SECRET_ACCESS_KEY"
	// envRootPassword is the optional root console password (#34).
	envRootPassword = "VWS_IAM_ROOT_PASSWORD"
)

const usage = `usage: vws-iam [flags]            serve gRPC
       vws-iam bootstrap [flags]  import the root key once and exit (idempotent)

-store=etcd reads systemd credentials from $CREDENTIALS_DIRECTORY: the etcd client TLS
(etcd-ca.pem, etcd-client.pem, etcd-client-key.pem) and the KEK (kek_active holding the
active id, kek_<id> the base64 of 32 bytes per key).
-store=memory KEK: env VWS_IAM_KEK (base64 of 32 bytes) + VWS_IAM_KEK_ID, -kek-dir, or a
random one.
Bootstrap root credentials: env VWS_IAM_ROOT_PROJECT, VWS_IAM_ROOT_ACCESS_KEY_ID,
VWS_IAM_ROOT_SECRET_ACCESS_KEY, or -root-credentials-dir. The root console password
is optional: env VWS_IAM_ROOT_PASSWORD, or a password file in -root-credentials-dir.
`

func parseConfig(args []string, stderr io.Writer, getenv func(string) string) (config, error) {
	c := config{getenv: getenv}
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
	fs.StringVar(&c.storeMode, "store", storeEtcd,
		"backend: etcd (shared by every replica) or memory (one process, lost on exit; never with replicas)")
	var endpoints string
	fs.StringVar(&endpoints, "etcd-endpoints", "", "comma-separated https://host:port etcd client URLs (-store=etcd)")
	fs.StringVar(&c.etcdPrefix, "etcd-prefix", "/vws/iam", "etcd key prefix of the IAM objects (-store=etcd)")
	fs.StringVar(&c.kekDir, "kek-dir", "",
		"-store=memory only: KEK directory of one base64 32-byte key per id and an \"active\" file")
	fs.StringVar(&c.rootDir, "root-credentials-dir", "",
		"optional mounted Secret with project, access_key_id and secret_access_key files: imported once as that "+
			"project's root key; an optional password file sets the root console password")
	fs.StringVar(&c.tls.certFile, "tls-cert-file", "", "PEM server certificate of the gRPC listener; "+
		"needs -tls-key-file and -tls-client-ca-file (mutual TLS)")
	fs.StringVar(&c.tls.keyFile, "tls-key-file", "", "PEM server key of the gRPC listener; "+
		"needs -tls-cert-file and -tls-client-ca-file")
	fs.StringVar(&c.tls.clientCAFile, "tls-client-ca-file", "", "PEM CA bundle that client certificates (console-api) "+
		"must chain to; a client without one is refused. The three TLS files are read again on every handshake")
	fs.BoolVar(&c.insecurePlaintext, "insecure-plaintext", false, "serve gRPC without TLS on a non-loopback -listen "+
		"address; only where another layer authenticates the channel")
	samlFlags(fs, &c.saml)
	fs.StringVar(&c.healthAddr, "health-listen", "127.0.0.1:9096", "HTTP address of /healthz and /readyz; empty disables")
	if err := fs.Parse(args); err != nil {
		return c, fmt.Errorf("flags: %w", err)
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	if err := c.checkStore(endpoints); err != nil {
		return c, fmt.Errorf("store config: %w", err)
	}
	if err := checkSAML(c.saml); err != nil {
		return c, fmt.Errorf("SAML config: %w", err)
	}
	if !c.bootstrap {
		if err := c.tls.check(c.listen, c.insecurePlaintext); err != nil {
			return c, fmt.Errorf("tls config: %w", err)
		}
	}
	hasEnvKEK := getenv(secret.EnvKEK) != "" || getenv(secret.EnvKEKID) != ""
	switch {
	case c.storeMode == storeEtcd && (hasEnvKEK || c.kekDir != ""):
		return c, fmt.Errorf("-store=etcd reads the KEK from $%s (%sactive, %s<id>), "+
			"not from VWS_IAM_KEK/VWS_IAM_KEK_ID or -kek-dir", envCredentials, credKEKPrefix, credKEKPrefix)
	case hasEnvKEK && c.kekDir != "":
		return c, errors.New("set either VWS_IAM_KEK/VWS_IAM_KEK_ID or -kek-dir, not both")
	case c.bootstrap && c.storeMode != storeEtcd:
		return c, errors.New("bootstrap needs -store=etcd")
	case c.bootstrap && c.rootDir == "" && getenv(envRootProject) == "":
		return c, errors.New("bootstrap needs root credentials (VWS_IAM_ROOT_* env or -root-credentials-dir)")
	}
	return c, nil
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

// openStore opens the backend and returns the function that closes it.
func openStore(cfg config) (store.Backend, func() error, error) {
	if cfg.storeMode == storeMemory {
		return memstore.New(), func() error { return nil }, nil
	}
	s, err := openEtcd(cfg)
	if err != nil {
		return nil, nil, err
	}
	return s, s.Close, nil
}

// keyring loads the KEK keyring: from the credential files with the etcd
// store; memory mode may use a random one.
func keyring(cfg config) (*secret.Keyring, error) {
	if cfg.storeMode == storeEtcd {
		k, err := secret.LoadPrefixed(cfg.credDir, credKEKPrefix)
		if err != nil {
			return nil, fmt.Errorf("load KEK keyring: %w", err)
		}
		return k, nil
	}
	if cfg.getenv != nil {
		k, ok, err := secret.FromEnv(cfg.getenv)
		if err != nil {
			return nil, fmt.Errorf("load KEK keyring: %w", err)
		}
		if ok {
			return k, nil
		}
	}
	if cfg.kekDir != "" {
		k, err := secret.LoadDir(cfg.kekDir)
		if err != nil {
			return nil, fmt.Errorf("load KEK keyring: %w", err)
		}
		return k, nil
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		return nil, fmt.Errorf("load KEK keyring: generate ephemeral key: %w", err)
	}
	k, err := secret.NewKeyring("ephemeral", map[string][]byte{"ephemeral": kek})
	if err != nil {
		return nil, fmt.Errorf("load KEK keyring: generate ephemeral key: %w", err)
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

// readRootPassword reads the optional password file of dir. Only the
// line ending is removed: spaces are part of a password.
func readRootPassword(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "password")) //nolint:gosec // operator-supplied mount path
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("root password: %w", err)
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
}

// bootstrapRoot imports the root key once and, when one is given, sets
// the root console password (#34). Nothing secret is logged.
func bootstrapRoot(ctx context.Context, b store.Backend, keys *secret.Keyring, cfg config) (_ string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("bootstrap root key: %w", err)
		}
	}()
	var project, id, sec, pw string
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
		if pw, err = readRootPassword(cfg.rootDir); err != nil {
			return "", err
		}
	} else {
		project = strings.TrimSpace(cfg.getenv(envRootProject))
		id = strings.TrimSpace(cfg.getenv(envRootKeyID))
		sec = strings.TrimSpace(cfg.getenv(envRootSecret))
		pw = cfg.getenv(envRootPassword)
	}
	if !iam.ValidProject(project) || !iam.ValidRootAccessKeyID(id) || len(sec) < 32 {
		return "", errors.New("root credentials: invalid project, access key id or secret")
	}
	svc := accesskey.New(store.Scoped(b, project), b, project, keys, nil)
	if _, err := svc.Import(ctx, "", id, sec, true); err != nil && !errors.Is(err, store.ErrExists) {
		return "", fmt.Errorf("root credentials: %w", err)
	}
	if pw == "" {
		return project, nil
	}
	changed, err := grpcapi.SetRootPassword(ctx, b, project, pw, time.Now())
	if err != nil {
		return "", fmt.Errorf("root credentials: %w", err)
	}
	slog.Default().LogAttrs(ctx, slog.LevelInfo, "root console password ready",
		slog.String("project", project), slog.Bool("changed", changed))
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
	backend, closeStore, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeStore()) }()
	if cfg.storeMode == storeMemory {
		log.LogAttrs(ctx, slog.LevelWarn, "state is in memory: not shared between replicas and lost on exit",
			slog.String("store", cfg.storeMode))
	}
	ready := storeReady(backend)
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
			return fmt.Errorf("start health server: %w", err)
		}
		defer func() { err = errors.Join(err, stopHealth(context.WithoutCancel(ctx))) }()
		log.LogAttrs(ctx, slog.LevelInfo, "health serving", slog.String("addr", bound))
	}

	var transport []grpc.ServerOption
	if cfg.tls.enabled() {
		tc, err := cfg.tls.serverConfig()
		if err != nil {
			return err
		}
		transport = append(transport, grpc.Creds(credentials.NewTLS(tc)))
	} else {
		log.LogAttrs(ctx, slog.LevelWarn,
			"gRPC is plaintext: set -tls-cert-file, -tls-key-file and -tls-client-ca-file for mutual TLS",
			slog.String("addr", cfg.listen))
	}
	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen gRPC: %w", err)
	}
	srv := grpc.NewServer(grpcapi.ServerOptions(transport...)...)
	api := grpcapi.New(backend, keys, apiOptions(cfg)...)
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
		slog.String("store", cfg.storeMode), slog.Bool("mtls", cfg.tls.enabled()),
		slog.Bool("saml", cfg.saml != (sts.SAMLServiceProvider{})))
	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("serve gRPC: %w", err)
	}
	return nil
}

// storeWaitAttempts bounds the startup store check: with a 1 s base the
// waits are 1, 2, 4, 8, 16 s, so about 30 s before giving up.
const storeWaitAttempts = 6

// waitStore checks the store before serving, retrying with exponential
// backoff, each try under its own deadline. An unreachable etcd or a
// refused client certificate fails startup instead of serving errors.
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

// storeReady reads at most one page: it runs on every health probe, and the
// key index grows with every live STS session (#188).
func storeReady(b store.Backend) func(context.Context) error {
	return func(ctx context.Context) error {
		var err error
		if p, ok := b.(store.Pager); ok {
			_, _, err = p.ListPage(ctx, iam.KindKeyIndex, 1, "")
		} else {
			_, err = b.List(ctx, iam.KindKeyIndex)
		}
		if err != nil {
			return fmt.Errorf("store: %w", err)
		}
		return nil
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
// counters whose window and lockout are over (#12), the key index entries
// of expired STS sessions (#188), and finishes renames
// cut short by a crash (#134), every few minutes. Each replica runs it; races between them are harmless.
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
		}{
			{"replay", api.GCReplayEntries},
			{"attempt", api.GCAttemptCounters},
			{"session key", api.GCSessionKeys},
			{"console session", api.GCConsoleSessions},
			{"rename", api.ResumeRenames},
		} {
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

// runBootstrap is the one-shot unit: open the store, import the root key
// (a no-op when it exists) and exit. It logs the project only.
func runBootstrap(ctx context.Context, cfg config) (err error) {
	keys, err := keyring(cfg)
	if err != nil {
		return err
	}
	backend, closeStore, err := openStore(cfg)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeStore()) }()
	project, err := bootstrapRoot(ctx, backend, keys, cfg)
	if err != nil {
		return err
	}
	slog.Default().LogAttrs(ctx, slog.LevelInfo, "bootstrap done", slog.String("project", project))
	return nil
}
