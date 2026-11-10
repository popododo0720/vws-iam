package grpcapi_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func TestCreateAccountAliasReclaimAdvancesSequence(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			ctx := t.Context()
			// Stop the first create after storing the record, before claiming it.
			failed := errors.New("claim unavailable")
			first := newEnvOn(t, stepStore{Backend: b, at: func(op string, k iam.Kind, _ string) error {
				if op == "create" && k == (iam.AccountAliasClaim{}).Kind() {
					return failed
				}
				return nil
			}}, &now)
			if err := first.api.CreateAccountAlias(ctx, proj, "aaa-requested"); err == nil {
				t.Fatal("claim failure was ignored")
			}
			before := storedAlias(t, b, proj, "aaa-requested")
			concurrent := newEnvOn(t, b, &now)
			interleaved := false
			retry := newEnvOn(t, stepStore{Backend: b, at: func(op string, k iam.Kind, key string) error {
				if !interleaved && op == "get" && k == (iam.AccountAlias{}).Kind() && key == proj+"/aaa-requested" {
					interleaved = true
					// A concurrent create can have chosen the same Seq before the first
					// record was stored. Complete its claim while the retry is reading.
					other := iam.AccountAlias{
						Meta:    iam.Meta{UID: iam.NewUID(), Generation: 1},
						Name:    "zzz-concurrent",
						Created: now,
						Seq:     before.Object.Seq,
					}
					if _, err := store.Create(ctx, store.Scoped(b, proj), other); err != nil {
						return err
					}
					_, err := store.Create(ctx, b, iam.AccountAliasClaim{Name: other.Name, Project: proj, UID: other.UID})
					return err
				}
				return nil
			}}, &now)
			if err := retry.api.CreateAccountAlias(ctx, proj, "aaa-requested"); err != nil {
				t.Fatal(err)
			}
			if !interleaved {
				t.Fatal("interleave did not run")
			}
			got := listedAliases(t, concurrent, proj)
			if !slices.Equal(got, []string{"aaa-requested"}) {
				t.Fatalf("listed %v, want requested alias", got)
			}
			after := storedAlias(t, b, proj, "aaa-requested")
			if after.Object.Seq <= before.Object.Seq || after.Object.UID != before.Object.UID {
				t.Fatalf("reclaimed %+v, before %+v", after.Object, before.Object)
			}
		})
	}
}
