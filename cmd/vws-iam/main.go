// Command vws-iam serves VWS identity and access management over gRPC.
//
// With -namespace set, users, groups, roles, policies, access keys, and MFA
// devices persist as iam.vws.popododo0720.io custom resources in that
// namespace; otherwise they live in memory.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"

	"github.com/popododo0720/vws-lib/obs"
	"github.com/popododo0720/vws-lib/obs/health"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/secret"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/kubestore"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

type config struct {
	listen, namespace, kubeconfig, kekDir string
}

func parseConfig(args []string, stderr io.Writer) (config, error) {
	fs := flag.NewFlagSet("vws-iam", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c config
	fs.StringVar(&c.listen, "listen", "127.0.0.1:9095", "gRPC listen address")
	fs.StringVar(&c.namespace, "namespace", "", "Kubernetes namespace of the IAM custom resources; empty keeps state in memory")
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "kubeconfig path; empty uses in-cluster config")
	fs.StringVar(&c.kekDir, "kek-dir", "", "directory of the mounted vws-iam-kek Secret: one base64 32-byte key per id and an \"active\" file")
	if err := fs.Parse(args); err != nil {
		return c, fmt.Errorf("flags: %w", err)
	}
	if fs.NArg() != 0 {
		return c, fmt.Errorf("unexpected arguments %q", fs.Args())
	}
	return c, nil
}

func main() {
	cfg, err := parseConfig(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vws-iam:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg); err != nil {
		slog.Default().LogAttrs(ctx, slog.LevelError, "vws-iam stopped", slog.String(obs.FieldErr, err.Error()))
		stop()
		os.Exit(1)
	}
}

func openStore(cfg config) (store.Backend, error) {
	if cfg.namespace == "" {
		return memstore.New(), nil
	}
	s, err := kubestore.Open(cfg.kubeconfig, cfg.namespace)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	return s, nil
}

func run(ctx context.Context, cfg config) (err error) {
	shutdown, err := obs.Setup(ctx, obs.ForService(grpcapi.ServiceName))
	if err != nil {
		return fmt.Errorf("obs setup: %w", err)
	}
	defer func() {
		if serr := shutdown(context.WithoutCancel(ctx)); serr != nil {
			err = errors.Join(err, fmt.Errorf("obs shutdown: %w", serr))
		}
	}()
	if cfg.kekDir != "" {
		keys, err := secret.LoadDir(cfg.kekDir)
		if err != nil {
			return err
		}
		slog.Default().LogAttrs(ctx, slog.LevelInfo, "loaded KEK keyring", slog.String("active_kek", keys.Active()))
	}
	backend, err := openStore(cfg)
	if err != nil {
		return err
	}
	ready := func(ctx context.Context) error {
		_, err := backend.List(ctx, iam.KindUser)
		return err
	}
	health.Default().Register("store", ready)

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	srv := grpc.NewServer(grpcapi.ServerOptions()...)
	h := grpcapi.RegisterHealth(srv, ready)
	go h.Run(ctx, 5*time.Second)
	go func() {
		<-ctx.Done()
		health.Default().NotReady()
		h.Shutdown()
		srv.GracefulStop()
	}()
	slog.Default().LogAttrs(ctx, slog.LevelInfo, "serving", slog.String("addr", lis.Addr().String()), slog.String("namespace", cfg.namespace))
	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
