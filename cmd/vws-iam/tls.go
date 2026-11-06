package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
)

// tlsFiles names the PEM files of the mutual TLS that secures the gRPC
// listener (#21), usually mounted from a Kubernetes Secret. They are read
// again on every handshake, so a rotated Secret takes effect on the next
// connection without a restart.
type tlsFiles struct {
	certFile, keyFile, clientCAFile string
}

func (f tlsFiles) enabled() bool {
	return f.certFile != "" || f.keyFile != "" || f.clientCAFile != ""
}

// check refuses a partial setting and plaintext on a non-loopback address
// unless insecurePlaintext says another layer authenticates the channel.
func (f tlsFiles) check(listen string, insecurePlaintext bool) error {
	switch {
	case f.enabled() && insecurePlaintext:
		return errors.New("-insecure-plaintext conflicts with -tls-cert-file, -tls-key-file and -tls-client-ca-file")
	case f.enabled() && (f.certFile == "" || f.keyFile == "" || f.clientCAFile == ""):
		return errors.New("mutual TLS needs all of -tls-cert-file, -tls-key-file and -tls-client-ca-file")
	case !f.enabled() && !insecurePlaintext && !loopback(listen):
		return fmt.Errorf("-listen %s is not a loopback address: set -tls-cert-file, -tls-key-file and "+
			"-tls-client-ca-file for mutual TLS, or -insecure-plaintext", listen)
	}
	return nil
}

// loopback reports whether addr only accepts connections from this host.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// serverConfig loads the files once, so a bad mount fails startup, and
// then again for every handshake. A client without a certificate signed
// by the client CA is refused before any RPC.
func (f tlsFiles) serverConfig() (*tls.Config, error) {
	if _, err := f.load(); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return f.load() },
	}, nil
}

func (f tlsFiles) load() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(f.certFile, f.keyFile)
	if err != nil {
		// The error names the files, never their contents.
		return nil, fmt.Errorf("load TLS server certificate: %w", err)
	}
	pem, err := os.ReadFile(f.clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read TLS client CA file: %w", err)
	}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("TLS client CA file %s holds no PEM certificate", f.clientCAFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    cas,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	}, nil
}
