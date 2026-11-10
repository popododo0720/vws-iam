package policy_test

import (
	"testing"

	"github.com/popododo0720/vws-iam/internal/policy"
)

func TestStatementPositions(t *testing.T) {
	doc := `{
  "Statement": [
    {
      "Effect":"Allow","Action":"s3:*","Resource":"*"
    },
    {
      "Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"
    }
  ]
}`
	d, err := policy.Parse(doc)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range [][2]policy.Position{
		{{Line: 3, Column: 5}, {Line: 5, Column: 5}},
		{{Line: 6, Column: 5}, {Line: 8, Column: 5}},
	} {
		s := d.Statements[i]
		if s.StartPosition != want[0] || s.EndPosition != want[1] {
			t.Errorf("statement %d: %v to %v, want %v", i, s.StartPosition, s.EndPosition, want)
		}
	}
	for _, doc := range []string{
		`{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`,
		`{"Id":"é","Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`,
		`{"Statement":{},"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`,
	} {
		d, err := policy.Parse(doc)
		if err != nil {
			t.Fatal(err)
		}
		s := d.Statements[0]
		// The column counts characters, including an unescaped non-ASCII Id.
		prefix := []rune(doc)
		wantStart := 0
		for i, r := range prefix {
			if r == '{' && i > 0 {
				wantStart = i + 1
			}
		}
		if s.StartPosition != (policy.Position{Line: 1, Column: wantStart}) ||
			s.EndPosition != (policy.Position{Line: 1, Column: len(prefix) - 1}) {
			t.Errorf("%s: %v to %v", doc, s.StartPosition, s.EndPosition)
		}
	}
}
