package sigv4_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/sigv4"
)

// The get-vanilla case of the AWS SigV4 test suite.
const (
	secret    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	canonical = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	sts       = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63"
	signature = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
)

var at = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

func vanilla() sigv4.Request {
	return sigv4.Request{Date: "20150830", Region: "us-east-1", Service: "service", CanonicalRequest: canonical, StringToSign: sts, Signature: signature}
}

func TestAWSSuiteGetVanilla(t *testing.T) {
	if got := sigv4.Sign([]byte(secret), "20150830", "us-east-1", "service", sts); got != signature {
		t.Fatalf("signature %s", got)
	}
	if err := sigv4.Check([]byte(secret), vanilla(), at); err != nil {
		t.Fatal(err)
	}
	r := vanilla()
	r.Signature = strings.ToUpper(r.Signature)
	if err := sigv4.Check([]byte(secret), r, at.Add(14*time.Minute)); err != nil {
		t.Fatalf("uppercase hex within skew: %v", err)
	}
}

func TestCheckRejects(t *testing.T) {
	mut := func(f func(*sigv4.Request)) sigv4.Request { r := vanilla(); f(&r); return r }
	cases := []struct {
		name string
		r    sigv4.Request
		now  time.Time
		want error
	}{
		{"wrong secret", vanilla(), at, sigv4.ErrSignature},
		{"tampered canonical request", mut(func(r *sigv4.Request) { r.CanonicalRequest += "x" }), at, sigv4.ErrHash},
		{"scope region", mut(func(r *sigv4.Request) { r.Region = "kr-central-1" }), at, sigv4.ErrScope},
		{"scope service", mut(func(r *sigv4.Request) { r.Service = "s3" }), at, sigv4.ErrScope},
		{"scope date", mut(func(r *sigv4.Request) { r.Date = "20150831" }), at, sigv4.ErrScope},
		{"algorithm", mut(func(r *sigv4.Request) {
			r.StringToSign = strings.Replace(r.StringToSign, "AWS4-HMAC-SHA256", "AWS4-HMAC-SHA1", 1)
		}), at, sigv4.ErrMalformed},
		{"extra line", mut(func(r *sigv4.Request) { r.StringToSign += "\n" }), at, sigv4.ErrMalformed},
		{"bad date", mut(func(r *sigv4.Request) {
			r.StringToSign = strings.Replace(r.StringToSign, "20150830T123600Z", "yesterday", 1)
		}), at, sigv4.ErrMalformed},
		{"too old", vanilla(), at.Add(16 * time.Minute), sigv4.ErrSkew},
		{"too new", vanilla(), at.Add(-16 * time.Minute), sigv4.ErrSkew},
		{"empty signature", mut(func(r *sigv4.Request) { r.Signature = "" }), at, sigv4.ErrSignature},
	}
	for _, c := range cases {
		s := secret
		if c.name == "wrong secret" {
			s = "not-the-secret"
		}
		if err := sigv4.Check([]byte(s), c.r, c.now); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}
