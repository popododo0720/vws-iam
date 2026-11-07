package grpcapi_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// samlTagsOf lists every tag of provider corp through e, one page.
func samlTagsOf(t *testing.T, e *env) map[string]string {
	t.Helper()
	page, err := e.api.ListSAMLProviderTags(t.Context(), proj, samlIdpARN, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.IsTruncated {
		t.Fatalf("one page of %d tags is truncated", len(page.Tags))
	}
	got := map[string]string{}
	for i, tg := range page.Tags {
		if i > 0 && page.Tags[i-1].Key >= tg.Key {
			t.Fatalf("tags not sorted by key: %v", page.Tags)
		}
		got[tg.Key] = tg.Value
	}
	return got
}

func wantSAMLTags(t *testing.T, e *env, want map[string]string) {
	t.Helper()
	if got := samlTagsOf(t, e); !maps.Equal(got, want) {
		t.Fatalf("tags %v, want %v", got, want)
	}
}

// TestSAMLProviderTags: tags written on one replica are listed by another
// started later (a restart reads the same store), sorted by key, keys case
// sensitive; Tag overwrites a value, Untag ignores a key the provider does
// not have, and a repeat of either writes nothing. A tag change keeps the
// name, UID, document and creation time and moves the generation. An ARN
// differing only in case, an unknown provider and another project's
// provider are NoSuchEntity and change nothing. On both store backends.
func TestSAMLProviderTags(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			f := newSAMLFixture(t, bk.open())
			writer := f.server(t)
			if _, err := writer.api.CreateSAMLProvider(t.Context(), proj, "corp", f.idp.Metadata(f.now.Add(time.Hour)),
				[]*iamv1.Tag{samlTag("team", "a")}); err != nil {
				t.Fatal(err)
			}
			f.create(t, writer, "beta")
			before := storedSAML(t, f.b, "corp")

			err := writer.api.TagSAMLProvider(t.Context(), proj, samlIdpARN,
				[]*iamv1.Tag{samlTag("team", "b"), samlTag("Env", "prod"), samlTag("env", "")})
			if err != nil {
				t.Fatal(err)
			}
			after := storedSAML(t, f.b, "corp")
			p := after.Object
			if p.UID != before.Object.UID || p.MetadataDocument != before.Object.MetadataDocument ||
				!p.Created.Equal(before.Object.Created) || p.Generation != before.Object.Generation+1 {
				t.Fatalf("stored after tag: %+v, want UID, document and creation kept, generation moved", p.Meta)
			}
			tagged := map[string]string{"team": "b", "Env": "prod", "env": ""}
			wantSAMLTags(t, f.server(t), tagged)
			if _, err := f.server(t).api.AssumeRoleWithSAML(t.Context(), f.signed(t, f.idp)); err != nil {
				t.Fatalf("AssumeRoleWithSAML after tagging: %v", err)
			}

			if err := writer.api.TagSAMLProvider(t.Context(), proj, samlIdpARN,
				[]*iamv1.Tag{samlTag("Env", "prod")}); err != nil {
				t.Fatalf("repeat tag: %v", err)
			}
			if v := storedSAML(t, f.b, "corp").Version; v != after.Version {
				t.Fatalf("a repeat tag wrote the provider: version %s, want %s", v, after.Version)
			}

			if err := writer.api.UntagSAMLProvider(t.Context(), proj, samlIdpARN, []string{"Env", "none"}); err != nil {
				t.Fatal(err)
			}
			delete(tagged, "Env")
			wantSAMLTags(t, f.server(t), tagged)
			untagged := storedSAML(t, f.b, "corp").Version
			if err := writer.api.UntagSAMLProvider(t.Context(), proj, samlIdpARN, []string{"Env", "none"}); err != nil {
				t.Fatalf("repeat untag: %v", err)
			}
			if v := storedSAML(t, f.b, "corp").Version; v != untagged {
				t.Fatalf("a repeat untag wrote the provider: version %s, want %s", v, untagged)
			}
			if err := writer.api.UntagSAMLProvider(t.Context(), proj, samlIdpARN, []string{"team", "env"}); err != nil {
				t.Fatal(err)
			}
			page, err := f.server(t).api.ListSAMLProviderTags(t.Context(), proj, samlIdpARN, "", 0)
			if err != nil || len(page.Tags) != 0 || page.IsTruncated || page.Marker != "" {
				t.Fatalf("untagged provider: %+v %v, want an empty complete page", page, err)
			}

			last := storedSAML(t, f.b, "corp").Version
			for _, arn := range []string{samlARN(proj, "CORP"), samlARN(proj, "other"), samlARN("beta", "corp")} {
				err := writer.api.TagSAMLProvider(t.Context(), proj, arn, []*iamv1.Tag{samlTag("k", "v")})
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
				err = writer.api.UntagSAMLProvider(t.Context(), proj, arn, []string{"k"})
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
				_, err = writer.api.ListSAMLProviderTags(t.Context(), proj, arn, "", 0)
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
			if v := storedSAML(t, f.b, "corp").Version; v != last {
				t.Fatal("a NoSuchEntity tag call wrote the provider")
			}
			other, err := store.Get[iam.SAMLProvider](t.Context(), store.Scoped(f.b, "beta"), "corp")
			if err != nil || len(other.Object.Tags) != 0 {
				t.Fatalf("another project's provider: %+v %v, want untouched", other.Object.Tags, err)
			}
		})
	}
}

// TestSAMLProviderTagLimits: a provider keeps at most 50 tags: tags up to
// 50 are stored, one more is LimitExceeded and writes nothing, an
// overwrite at 50 succeeds, and a key repeated within one request keeps
// its last value and counts once. A tag that would make the provider too
// large to store is InvalidInput and writes nothing.
func TestSAMLProviderTagLimits(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	seedSAML(t, b, &now)
	e := newEnvOn(t, b, &now)
	var tags []*iamv1.Tag
	want := map[string]string{}
	for i := range iam.MaxSAMLProviderTags - 1 {
		k := fmt.Sprintf("k%02d", i)
		tags = append(tags, samlTag(k, "v"))
		want[k] = "v"
	}
	if err := e.api.TagSAMLProvider(t.Context(), proj, samlIdpARN, tags); err != nil {
		t.Fatal(err)
	}
	repeated := []*iamv1.Tag{samlTag("last", "1"), samlTag("last", "2"), samlTag("last", "3")}
	if err := e.api.TagSAMLProvider(t.Context(), proj, samlIdpARN, repeated); err != nil {
		t.Fatalf("the 50th tag repeated in one request: %v", err)
	}
	want["last"] = "3"
	wantSAMLTags(t, e, want)

	full := storedSAML(t, b, "corp").Version
	err := e.api.TagSAMLProvider(t.Context(), proj, samlIdpARN, []*iamv1.Tag{samlTag("k00", "w"), samlTag("new", "v")})
	wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
	if v := storedSAML(t, b, "corp").Version; v != full {
		t.Fatal("a LimitExceeded tag wrote the provider")
	}
	if err := e.api.TagSAMLProvider(t.Context(), proj, samlIdpARN, []*iamv1.Tag{samlTag("k00", "w")}); err != nil {
		t.Fatalf("overwrite at 50 tags: %v", err)
	}
	want["k00"] = "w"
	wantSAMLTags(t, e, want)

	// <, > and & are six bytes each once encoded, so this document fits
	// one custom resource with no tags but not with 256-character values.
	big := plainSAMLDoc(strings.Repeat("<&>", (iam.MaxSAMLProviderEncodedLen-4000)/18))
	if _, err := e.api.CreateSAMLProvider(t.Context(), proj, "big", big, nil); err != nil {
		t.Fatal(err)
	}
	var wide []*iamv1.Tag
	for i := range 20 {
		wide = append(wide, samlTag(fmt.Sprintf("k%02d", i), strings.Repeat("v", iam.MaxTagValueLen)))
	}
	bigARN := samlARN(proj, "big")
	stored := storedSAML(t, b, "big").Version
	err = e.api.TagSAMLProvider(t.Context(), proj, bigARN, wide)
	wantAWS(t, err, codes.InvalidArgument, "InvalidInput")
	if v := storedSAML(t, b, "big").Version; v != stored {
		t.Fatal("a tag too large to store wrote the provider")
	}
}

// TestSAMLProviderTagsPages: MaxItems bounds every page, a truncated page
// carries a marker, and the pages together hold every tag once, in key
// order; 0 is the AWS default of 100, which holds all 50. A tag added or
// removed between pages shifts nothing already listed. On both store
// backends.
func TestSAMLProviderTagsPages(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			seedSAML(t, b, &now)
			e := newEnvOn(t, b, &now)
			var tags []*iamv1.Tag
			for i := range iam.MaxSAMLProviderTags {
				tags = append(tags, samlTag(fmt.Sprintf("k%02d", i), fmt.Sprint(i)))
			}
			if err := e.api.TagSAMLProvider(t.Context(), proj, samlIdpARN, tags); err != nil {
				t.Fatal(err)
			}
			if got := samlTagsOf(t, e); len(got) != iam.MaxSAMLProviderTags {
				t.Fatalf("default page holds %d tags, want %d", len(got), iam.MaxSAMLProviderTags)
			}
			for _, n := range []int{1, 7, 49, 50} {
				var keys []string
				marker := ""
				for pages := 1; ; pages++ {
					page, err := e.api.ListSAMLProviderTags(t.Context(), proj, samlIdpARN, marker, n)
					if err != nil {
						t.Fatal(err)
					}
					if len(page.Tags) > n || (page.IsTruncated && page.Marker == "") || pages > iam.MaxSAMLProviderTags {
						t.Fatalf("page of %d: %d tags, truncated %v, marker %q", n, len(page.Tags), page.IsTruncated, page.Marker)
					}
					for _, tg := range page.Tags {
						keys = append(keys, tg.Key)
					}
					if !page.IsTruncated {
						break
					}
					marker = page.Marker
				}
				if len(keys) != iam.MaxSAMLProviderTags {
					t.Fatalf("pages of %d: %d tags, want %d", n, len(keys), iam.MaxSAMLProviderTags)
				}
				for i, k := range keys {
					if k != fmt.Sprintf("k%02d", i) {
						t.Fatalf("pages of %d: key %d is %q", n, i, k)
					}
				}
			}

			first, err := e.api.ListSAMLProviderTags(t.Context(), proj, samlIdpARN, "", 2)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.api.UntagSAMLProvider(t.Context(), proj, samlIdpARN, []string{"k00", "k02"}); err != nil {
				t.Fatal(err)
			}
			if err := e.api.TagSAMLProvider(t.Context(), proj, samlIdpARN, []*iamv1.Tag{samlTag("a", "early")}); err != nil {
				t.Fatal(err)
			}
			second, err := e.api.ListSAMLProviderTags(t.Context(), proj, samlIdpARN, first.Marker, 2)
			if err != nil || len(second.Tags) != 2 || second.Tags[0].Key != "k03" || second.Tags[1].Key != "k04" {
				t.Fatalf("page after changes: %+v %v, want k03 and k04", second.Tags, err)
			}
		})
	}
}

// TestSAMLProviderTagsConcurrent: tags of different keys written at once
// on two replicas are all kept, and racing equal tags all succeed and
// write once. On both store backends.
func TestSAMLProviderTagsConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			seedSAML(t, b, &now)
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			// At most maxDeleteAttempts writers: each lost race is another
			// writer's success, so every one commits within its attempts.
			errs := make([]error, 8)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.TagSAMLProvider(t.Context(), proj, samlIdpARN,
						[]*iamv1.Tag{samlTag(fmt.Sprintf("k%d", i), "v")})
				})
			}
			wg.Wait()
			want := map[string]string{}
			for i, err := range errs {
				if err != nil {
					t.Fatalf("tag %d: %v", i, err)
				}
				want[fmt.Sprintf("k%d", i)] = "v"
			}
			wantSAMLTags(t, replicas[0], want)

			gen := storedSAML(t, b, "corp").Object.Generation
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.TagSAMLProvider(t.Context(), proj, samlIdpARN,
						[]*iamv1.Tag{samlTag("same", "v")})
				})
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("equal tag %d: %v", i, err)
				}
			}
			if g := storedSAML(t, b, "corp").Object.Generation; g != gen+1 {
				t.Fatalf("generation %d after racing equal tags, want %d", g, gen+1)
			}
		})
	}
}

// TestSAMLProviderTagsStaleRead: a provider written after it was read is
// read again and then tagged or untagged, keeping the other writer's
// change; one that keeps changing is ConcurrentModification and keeps its
// tags. On both store backends.
func TestSAMLProviderTagsStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedSAML(t, inner, &now)
			b := &changingSAMLBeforeUpdate{Backend: inner, n: 1, t: t}
			if err := newEnvOn(t, b, &now).api.TagSAMLProvider(t.Context(), proj, samlIdpARN,
				[]*iamv1.Tag{samlTag("mine", "v")}); err != nil {
				t.Fatalf("tag after one concurrent write: %v", err)
			}
			want := map[string]string{"writer": "other", "mine": "v"}
			if got := storedSAML(t, inner, "corp").Object.Tags; !maps.Equal(got, want) {
				t.Fatalf("stored tags %v, want the other writer's and this one", got)
			}
			b = &changingSAMLBeforeUpdate{Backend: inner, n: 1, t: t}
			if err := newEnvOn(t, b, &now).api.UntagSAMLProvider(t.Context(), proj, samlIdpARN,
				[]string{"writer"}); err != nil {
				t.Fatalf("untag after one concurrent write: %v", err)
			}
			if got := storedSAML(t, inner, "corp").Object.Tags; len(got) != 0 {
				t.Fatalf("stored tags %v, want none", got)
			}

			b = &changingSAMLBeforeUpdate{Backend: inner, n: 1 << 30, t: t}
			err := newEnvOn(t, b, &now).api.TagSAMLProvider(t.Context(), proj, samlIdpARN,
				[]*iamv1.Tag{samlTag("lost", "v")})
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			if _, ok := storedSAML(t, inner, "corp").Object.Tags["lost"]; ok {
				t.Fatal("a ConcurrentModification tag was stored")
			}
		})
	}
}

// TestSAMLProviderTagsCanceled: a canceled tag or untag writes nothing, and
// the same request afterwards applies.
func TestSAMLProviderTagsCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	seedSAML(t, b, &now)
	e := newEnvOn(t, b, &now)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	tags := []*iamv1.Tag{samlTag("k", "v")}
	if err := e.api.TagSAMLProvider(canceled, proj, samlIdpARN, tags); err == nil {
		t.Fatal("a canceled tag succeeded")
	}
	if len(storedSAML(t, b, "corp").Object.Tags) != 0 {
		t.Fatal("a canceled tag wrote the provider")
	}
	if err := e.api.TagSAMLProvider(t.Context(), proj, samlIdpARN, tags); err != nil {
		t.Fatalf("the same tag afterwards: %v", err)
	}
	if err := e.api.UntagSAMLProvider(canceled, proj, samlIdpARN, []string{"k"}); err == nil {
		t.Fatal("a canceled untag succeeded")
	}
	if len(storedSAML(t, b, "corp").Object.Tags) != 1 {
		t.Fatal("a canceled untag wrote the provider")
	}
	if err := e.api.UntagSAMLProvider(t.Context(), proj, samlIdpARN, []string{"k"}); err != nil {
		t.Fatalf("the same untag afterwards: %v", err)
	}
	if len(storedSAML(t, b, "corp").Object.Tags) != 0 {
		t.Fatal("the untag did not remove the tag")
	}
}

// TestSAMLProviderTagErrors: request faults are answered before any store
// access (the store here fails every read): a bad project, a bad ARN, no
// or more than 50 tags or keys and a bad maxItems or marker character are
// ValidationError; an ARN that is not a SAML provider ARN, a tag or key
// outside the AWS tag rules and a marker this service did not issue are
// InvalidInput; another account's ARN is NoSuchEntity. A store failure is
// ServiceFailure or ServiceUnavailable and a stored document that no
// longer parses ServiceFailure without its content. None writes.
func TestSAMLProviderTagErrors(t *testing.T) {
	inner := memstore.New()
	now := time.Now().UTC()
	seedSAML(t, inner, &now)
	stored := storedSAML(t, inner, "corp").Version
	down := newEnvOn(t, failingGet{Backend: inner, k: iam.KindSAMLProvider, err: store.ErrUnavailable}, &now)
	ok := []*iamv1.Tag{samlTag("k", "v")}
	var tooMany []*iamv1.Tag
	var tooManyKeys []string
	for i := range iam.MaxSAMLProviderTags + 1 {
		tooMany = append(tooMany, samlTag(fmt.Sprint(i), "v"))
		tooManyKeys = append(tooManyKeys, fmt.Sprint(i))
	}
	argCases := []struct {
		name, pid, arn string
		tags           []*iamv1.Tag
		keys           []string // nil: the case is not one of Untag
		list           bool     // the case is one of ListSAMLProviderTags too
		code           codes.Code
		aws            string
	}{
		{"bad project", "Bad Project", samlIdpARN, ok, []string{"k"}, true, codes.InvalidArgument, "ValidationError"},
		{"short ARN", proj, strings.Repeat("a", 19), ok, []string{"k"}, true, codes.InvalidArgument, "ValidationError"},
		{"role ARN", proj, samlRoleARN, ok, []string{"k"}, true, codes.InvalidArgument, "InvalidInput"},
		{"another account", proj, samlARN("beta", "corp"), ok, []string{"k"}, true, codes.NotFound, "NoSuchEntity"},
		{"none", proj, samlIdpARN, nil, []string{}, false, codes.InvalidArgument, "ValidationError"},
		{"51", proj, samlIdpARN, tooMany, tooManyKeys, false, codes.InvalidArgument, "ValidationError"},
		{
			"empty key", proj, samlIdpARN,
			[]*iamv1.Tag{samlTag("", "v")},
			[]string{""},
			false,
			codes.InvalidArgument, "InvalidInput",
		},
		{
			"aws: prefix", proj, samlIdpARN,
			[]*iamv1.Tag{samlTag("aws:k", "v")},
			[]string{"aws:k"},
			false,
			codes.InvalidArgument, "InvalidInput",
		},
		{
			"key of 129", proj, samlIdpARN,
			[]*iamv1.Tag{samlTag(strings.Repeat("k", 129), "v")},
			[]string{strings.Repeat("k", 129)},
			false, codes.InvalidArgument, "InvalidInput",
		},
		{
			"bad key character", proj, samlIdpARN,
			[]*iamv1.Tag{samlTag("k!", "v")},
			[]string{"k!"},
			false,
			codes.InvalidArgument, "InvalidInput",
		},
		{
			"value of 257", proj, samlIdpARN,
			[]*iamv1.Tag{samlTag("k", strings.Repeat("v", 257))},
			nil, false,
			codes.InvalidArgument, "InvalidInput",
		},
		{"store down", proj, samlIdpARN, ok, []string{"k"}, true, codes.Unavailable, "ServiceUnavailable"},
	}
	for _, c := range argCases {
		t.Run(c.name, func(t *testing.T) {
			err := down.api.TagSAMLProvider(t.Context(), c.pid, c.arn, c.tags)
			wantAWS(t, err, c.code, c.aws)
			if c.keys != nil {
				err = down.api.UntagSAMLProvider(t.Context(), c.pid, c.arn, c.keys)
				wantAWS(t, err, c.code, c.aws)
			}
			if c.list {
				_, err = down.api.ListSAMLProviderTags(t.Context(), c.pid, c.arn, "", 0)
				wantAWS(t, err, c.code, c.aws)
			}
			if v := storedSAML(t, inner, "corp").Version; v != stored {
				t.Fatal("a refused tag call wrote the provider")
			}
		})
	}

	listCases := []struct {
		name, marker string
		maxItems     int
		code         codes.Code
		aws          string
	}{
		{"maxItems 1001", "", 1001, codes.InvalidArgument, "ValidationError"},
		{"maxItems -1", "", -1, codes.InvalidArgument, "ValidationError"},
		{"marker control character", "a\n", 0, codes.InvalidArgument, "ValidationError"},
		{"marker not issued", "!!!", 0, codes.InvalidArgument, "InvalidInput"},
	}
	for _, c := range listCases {
		t.Run(c.name, func(t *testing.T) {
			_, err := down.api.ListSAMLProviderTags(t.Context(), proj, samlIdpARN, c.marker, c.maxItems)
			wantAWS(t, err, c.code, c.aws)
		})
	}
	if _, err := newEnvOn(t, inner, &now).api.ListSAMLProviderTags(t.Context(), proj, samlIdpARN, "", 1000); err != nil {
		t.Fatalf("maxItems 1000: %v", err)
	}

	boom := errors.New("backend down")
	failures := []struct {
		name string
		b    store.Backend
	}{
		{"read fails", failingGet{Backend: inner, k: iam.KindSAMLProvider, err: boom}},
		{"write fails", failingUpdate{Backend: inner, k: iam.KindSAMLProvider, err: boom}},
		{"corrupt document", corruptSAMLGet{Backend: inner}},
	}
	for _, c := range failures {
		t.Run(c.name, func(t *testing.T) {
			e := newEnvOn(t, c.b, &now)
			err := e.api.TagSAMLProvider(t.Context(), proj, samlIdpARN, ok)
			wantAWS(t, err, codes.Internal, "ServiceFailure")
			if strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("error carries the document: %v", err)
			}
			if c.name == "read fails" {
				_, err = e.api.ListSAMLProviderTags(t.Context(), proj, samlIdpARN, "", 0)
				wantAWS(t, err, codes.Internal, "ServiceFailure")
			}
			if v := storedSAML(t, inner, "corp").Version; v != stored {
				t.Fatal("a failed tag call wrote the provider")
			}
		})
	}
}
