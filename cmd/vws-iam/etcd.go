package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/popododo0720/vws-iam/internal/store/etcdstore"
)

// Credential files of -store=etcd that the systemd unit loads into
// $CREDENTIALS_DIRECTORY (LoadCredential=). The KEK is a directory
// credential: kek_active holds the active id, kek_<id> each key.
const (
	envCredentials = "CREDENTIALS_DIRECTORY"
	credEtcdCA     = "etcd-ca.pem"
	credEtcdCert   = "etcd-client.pem"
	credEtcdKey    = "etcd-client-key.pem"
	credKEKPrefix  = "kek_"
)

var etcdPrefixRE = regexp.MustCompile(`^(/[A-Za-z0-9._-]+)+$`)

// checkStore validates -store and, for etcd, its endpoints, key prefix
// and credentials directory.
func (c *config) checkStore(endpoints string) error {
	switch c.storeMode {
	case storeMemory:
		if endpoints != "" {
			return errors.New("-store=memory conflicts with -etcd-endpoints")
		}
		return nil
	case storeEtcd:
	default:
		return fmt.Errorf("-store must be %s or %s, not %q", storeEtcd, storeMemory, c.storeMode)
	}
	if endpoints == "" {
		return errors.New("-store=etcd needs -etcd-endpoints")
	}
	for e := range strings.SplitSeq(endpoints, ",") {
		u, err := url.Parse(strings.TrimSpace(e))
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Port() == "" || u.User != nil ||
			u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("-etcd-endpoints: %q is not an https://host:port URL", e)
		}
		c.etcdEndpoints = append(c.etcdEndpoints, u.String())
	}
	if !etcdPrefixRE.MatchString(c.etcdPrefix) {
		return fmt.Errorf("-etcd-prefix %q is not of the form /name[/name...]", c.etcdPrefix)
	}
	c.credDir = c.getenv(envCredentials)
	if c.credDir == "" {
		return fmt.Errorf("-store=etcd reads the etcd client TLS and the KEK from $%s "+
			"(systemd LoadCredential=), which is not set", envCredentials)
	}
	return nil
}

// openEtcd connects the etcd store with the client TLS of the credential
// files.
func openEtcd(cfg config) (*etcdstore.Store, error) {
	tc, err := etcdTLS(cfg.credDir)
	if err != nil {
		return nil, err
	}
	s, err := etcdstore.Open(cfg.etcdEndpoints, tc, cfg.etcdPrefix)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	return s, nil
}

// etcdTLS reads the client certificate etcd authenticates and the CA its
// server certificate must chain to, once at startup. Errors name the
// files, never their contents.
func etcdTLS(dir string) (*tls.Config, error) {
	certPath, keyPath := filepath.Join(dir, credEtcdCert), filepath.Join(dir, credEtcdKey)
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("etcd client certificate %s and key %s: %w", certPath, keyPath, err)
	}
	caPath := filepath.Join(dir, credEtcdCA)
	pem, err := os.ReadFile(caPath) //nolint:gosec // systemd credentials directory
	if err != nil {
		return nil, fmt.Errorf("etcd CA: %w", err)
	}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("etcd CA %s holds no PEM certificate", caPath)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: cas, MinVersion: tls.VersionTLS12}, nil
}
