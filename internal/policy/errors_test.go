package policy_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/policy"
)

// stmt wraps one statement in a policy document.
func stmt(s string) string { return `{"Version":"2012-10-17","Statement":{` + s + `}}` }

func TestParseErrorsNameTheField(t *testing.T) {
	cond := `"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":`
	for _, c := range []struct {
		doc, want string
		parse     func(string) (*policy.Document, error)
	}{
		{stmt(`"Effect":"Allow","Action":[],"Resource":"*"`), "action: ", policy.ParseIdentity},
		{stmt(`"Effect":"Allow","Action":"s3:*","Resource":[]`), "resource: ", policy.ParseIdentity},
		{stmt(cond + `{"StringEquals":{"s3:prefix":[]}}`), `condition StringEquals key "s3:prefix": `, policy.ParseIdentity},
		{
			stmt(cond + `{"Bool":{"aws:SecureTransport":"yes"}}`), `condition Bool key "aws:SecureTransport": `,
			policy.ParseIdentity,
		},
		{stmt(`"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":[]}`), "principal AWS: ", policy.ParseTrust},
	} {
		_, err := c.parse(c.doc)
		if !errors.Is(err, policy.ErrMalformed) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q wrapping ErrMalformed", c.doc, err, c.want)
		}
	}
}
