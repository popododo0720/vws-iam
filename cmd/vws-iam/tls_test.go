package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf returns a certificate and key PEM signed by ca.
func (ca testCA) leaf(t *testing.T, name string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: k})
}

func (ca testCA) client(t *testing.T) tls.Certificate {
	t.Helper()
	c, k := ca.leaf(t, "console-api", x509.ExtKeyUsageClientAuth)
	cert, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// serverFiles writes a server certificate signed by serverCA and the
// client CA bundle into dir, as a mounted Secret would.
func serverFiles(t *testing.T, dir string, serverCA, clientCA testCA) tlsFiles {
	t.Helper()
	f := tlsFiles{
		certFile: filepath.Join(dir, "tls.crt"), keyFile: filepath.Join(dir, "tls.key"),
		clientCAFile: filepath.Join(dir, "ca.crt"),
	}
	c, k := serverCA.leaf(t, "vws-iam", x509.ExtKeyUsageServerAuth)
	writeFile(t, f.certFile, c)
	writeFile(t, f.keyFile, k)
	writeFile(t, f.clientCAFile, clientCA.pem)
	return f
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// serve runs the real server (memory store) with args and stops it at
// the end of the test.
func serve(t *testing.T, args ...string) string {
	t.Helper()
	addr := freeAddr(t)
	args = append([]string{"-store=memory", "-health-listen=", "-listen", addr}, args...)
	cfg, err := parseConfig(args, io.Discard, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("run: %v", err)
		}
	})
	return addr
}

// check makes one health call on a new connection.
func check(addr string, creds credentials.TransportCredentials) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return errors.Join(err, conn.Close())
}

func mtlsClient(serverCA testCA, cert *tls.Certificate) credentials.TransportCredentials {
	roots := x509.NewCertPool()
	roots.AddCert(serverCA.cert)
	cfg := &tls.Config{RootCAs: roots, ServerName: "vws-iam", MinVersion: tls.VersionTLS12}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return credentials.NewTLS(cfg)
}

// waitServing retries until the server answers, as it starts in the
// background.
func waitServing(t *testing.T, addr string, creds credentials.TransportCredentials) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := check(addr, creds)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never answered a trusted client: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestMutualTLS is #21: with the TLS flags only a client presenting a
// certificate from the client CA reaches an RPC.
func TestMutualTLS(t *testing.T) {
	serverCA, clientCA, otherCA := newCA(t, "server-ca"), newCA(t, "client-ca"), newCA(t, "other-ca")
	f := serverFiles(t, t.TempDir(), serverCA, clientCA)
	addr := serve(t, "-tls-cert-file", f.certFile, "-tls-key-file", f.keyFile, "-tls-client-ca-file", f.clientCAFile)

	good := clientCA.client(t)
	waitServing(t, addr, mtlsClient(serverCA, &good))

	other := otherCA.client(t)
	serverCAClient := serverCA.client(t)
	for name, creds := range map[string]credentials.TransportCredentials{
		"plaintext":                    insecure.NewCredentials(),
		"no client certificate":        mtlsClient(serverCA, nil),
		"certificate of another CA":    mtlsClient(serverCA, &other),
		"server CA, not the client CA": mtlsClient(serverCA, &serverCAClient),
		"client distrusts server":      mtlsClient(otherCA, &good),
	} {
		if err := check(addr, creds); err == nil {
			t.Errorf("%s: call succeeded", name)
		}
	}
}

// TestMutualTLSRotation is #21: a rotated Secret (new server certificate
// and client CA) applies to the next connection without a restart, and
// the old client CA no longer admits anyone.
func TestMutualTLSRotation(t *testing.T) {
	serverCA, clientCA := newCA(t, "server-ca"), newCA(t, "client-ca")
	dir := t.TempDir()
	f := serverFiles(t, dir, serverCA, clientCA)
	addr := serve(t, "-tls-cert-file", f.certFile, "-tls-key-file", f.keyFile, "-tls-client-ca-file", f.clientCAFile)
	oldClient := clientCA.client(t)
	waitServing(t, addr, mtlsClient(serverCA, &oldClient))

	newServerCA, newClientCA := newCA(t, "server-ca-2"), newCA(t, "client-ca-2")
	serverFiles(t, dir, newServerCA, newClientCA)
	newClient := newClientCA.client(t)
	if err := check(addr, mtlsClient(newServerCA, &newClient)); err != nil {
		t.Fatalf("rotated certificates not used: %v", err)
	}
	if err := check(addr, mtlsClient(newServerCA, &oldClient)); err == nil {
		t.Fatal("client of the old CA still accepted after rotation")
	}
	if err := check(addr, mtlsClient(serverCA, &newClient)); err == nil {
		t.Fatal("old server certificate still served after rotation")
	}

	// A broken file mid-rotation refuses connections; it never falls
	// back to plaintext or to no client verification.
	writeFile(t, f.clientCAFile, []byte("not pem"))
	if err := check(addr, mtlsClient(newServerCA, &newClient)); err == nil {
		t.Fatal("handshake succeeded with an unreadable client CA")
	}
	if err := check(addr, insecure.NewCredentials()); err == nil {
		t.Fatal("plaintext accepted with an unreadable client CA")
	}
}

func TestTLSFlags(t *testing.T) {
	dir := t.TempDir()
	f := serverFiles(t, dir, newCA(t, "s"), newCA(t, "c"))
	all := []string{"-tls-cert-file", f.certFile, "-tls-key-file", f.keyFile, "-tls-client-ca-file", f.clientCAFile}
	for _, tc := range []struct {
		args []string
		err  string
	}{
		{nil, ""},
		{[]string{"-listen", "[::1]:9095"}, ""},
		{[]string{"-listen", "localhost:9095"}, ""},
		{[]string{"-listen", "0.0.0.0:9095"}, "not a loopback address"},
		{[]string{"-listen", ":9095"}, "not a loopback address"},
		{[]string{"-listen", "10.0.0.1:9095"}, "not a loopback address"},
		{[]string{"-listen", "garbage"}, "not a loopback address"},
		{[]string{"-listen", "0.0.0.0:9095", "-insecure-plaintext"}, ""},
		{append([]string{"-listen", "0.0.0.0:9095"}, all...), ""},
		{append([]string{"-insecure-plaintext"}, all...), "conflicts"},
		{all[:2], "needs all of"},
		{all[:4], "needs all of"},
		{all[2:], "needs all of"},
	} {
		_, err := parseConfig(append([]string{"-store=memory"}, tc.args...), io.Discard, noEnv)
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%q: got %v, want %q", tc.args, err, tc.err)
		}
	}

	// bootstrap serves nothing, so the chart's listen flag needs no TLS there.
	kek := map[string]string{envRootProject: "acme"}
	boot := []string{"bootstrap", "-store=kube", "-namespace", "ns", "-kek-dir", "/k", "-listen", "0.0.0.0:1"}
	if _, err := parseConfig(boot, io.Discard, envOf(kek)); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
}

// TestTLSBadFilesFailStartup: a missing or invalid mount stops the
// process before it listens instead of on the first connection.
func TestTLSBadFilesFailStartup(t *testing.T) {
	dir := t.TempDir()
	good := serverFiles(t, dir, newCA(t, "s"), newCA(t, "c"))
	notPEM := filepath.Join(dir, "bad.pem")
	writeFile(t, notPEM, []byte("not pem"))
	for name, f := range map[string]tlsFiles{
		"missing cert":   {filepath.Join(dir, "absent"), good.keyFile, good.clientCAFile},
		"mismatched key": {good.certFile, notPEM, good.clientCAFile},
		"missing CA":     {good.certFile, good.keyFile, filepath.Join(dir, "absent")},
		"CA not PEM":     {good.certFile, good.keyFile, notPEM},
	} {
		addr := freeAddr(t)
		args := []string{
			"-store=memory", "-health-listen=", "-listen", addr,
			"-tls-cert-file", f.certFile, "-tls-key-file", f.keyFile, "-tls-client-ca-file", f.clientCAFile,
		}
		cfg, err := parseConfig(args, io.Discard, noEnv)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = run(ctx, cfg)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "TLS") {
			t.Errorf("%s: run returned %v", name, err)
		}
		if strings.Contains(err.Error(), "PRIVATE KEY-----") {
			t.Errorf("%s: error carries key material: %v", name, err)
		}
	}
}
