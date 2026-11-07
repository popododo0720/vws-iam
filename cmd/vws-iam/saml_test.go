package main

import (
	"io"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/grpcapi"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

const (
	testAudience  = "urn:amazon:webservices"
	testSignInURL = "https://signin.vws.example/saml"
)

// TestSAMLFlags: -saml-audience and -saml-sign-in-url are both set or
// neither; the audience is an absolute URI, the sign-in URL an https URL
// with a host and no user info, query or fragment; both are bounded and
// refuse spaces, control characters and invalid UTF-8; accepted values
// are kept byte for byte.
func TestSAMLFlags(t *testing.T) {
	long := "https://h.example/" + strings.Repeat("a", maxSAMLValueLen)
	for _, tc := range []struct {
		audience, signIn string
		err              string
	}{
		{"", "", ""},
		{testAudience, testSignInURL, ""},
		{"https://vws.example/sp", "https://signin.vws.example:8443/saml", ""},
		{testAudience, "", "needs both"},
		{"", testSignInURL, "needs both"},
		{"vws", testSignInURL, "absolute URI"},
		{"/relative", testSignInURL, "absolute URI"},
		{"urn:", testSignInURL, "absolute URI"},
		{"https://", testSignInURL, "absolute URI"},
		{"urn:a b", testSignInURL, "without spaces"},
		{"urn:a\x00", testSignInURL, "without spaces"},
		{"urn:a\xff", testSignInURL, "UTF-8"},
		{long, testSignInURL, "at most"},
		{testAudience, "http://signin.vws.example/saml", "https URL"},
		{testAudience, "https:///saml", "https URL"},
		{testAudience, "https://user:pw@signin.vws.example/saml", "https URL"},
		{testAudience, "https://signin.vws.example/saml?x=1", "https URL"},
		{testAudience, "https://signin.vws.example/saml#f", "https URL"},
		{testAudience, "signin.vws.example/saml", "https URL"},
		{testAudience, "https://signin.vws.example/\tsaml", "without spaces"},
		{testAudience, long, "at most"},
	} {
		args := []string{"-store=memory", "-saml-audience", tc.audience, "-saml-sign-in-url", tc.signIn}
		cfg, err := parseConfig(args, io.Discard, noEnv)
		if tc.err == "" && err != nil || tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)) {
			t.Errorf("%q %q: got %v, want %q", tc.audience, tc.signIn, err, tc.err)
			continue
		}
		if err == nil && (cfg.saml.Audience != tc.audience || cfg.saml.SignInURL != tc.signIn) {
			t.Errorf("%q %q: kept %+v", tc.audience, tc.signIn, cfg.saml)
		}
	}
}

// TestSAMLReachesServer: the flag values are the server's SAML service
// provider (grpcapi.WithStoredSAML, whose behaviour grpcapi tests), and
// without the flags it has none, so AssumeRoleWithSAML stays refused.
func TestSAMLReachesServer(t *testing.T) {
	for _, args := range [][]string{
		{"-store=memory", "-saml-audience", testAudience, "-saml-sign-in-url", testSignInURL},
		{"-store=memory"},
	} {
		cfg, err := parseConfig(args, io.Discard, noEnv)
		if err != nil {
			t.Fatal(err)
		}
		got := grpcapi.New(memstore.New(), nil, apiOptions(cfg)...).SAMLServiceProvider()
		if got != cfg.saml {
			t.Fatalf("%q: server has %+v, want %+v", args, got, cfg.saml)
		}
	}
}
