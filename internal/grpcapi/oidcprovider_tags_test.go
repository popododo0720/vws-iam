package grpcapi_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/popododo0720/vws-proto/gen/go/vws/iam/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
	"github.com/popododo0720/vws-iam/internal/store/memstore"
)

// oidcTagsOf lists every tag of the provider arn names through e, one page.
func oidcTagsOf(t *testing.T, e *env, arn string) map[string]string {
	t.Helper()
	page, err := e.api.ListOpenIDConnectProviderTags(t.Context(), proj, arn, "", 0)
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

func wantOIDCTags(t *testing.T, e *env, arn string, want map[string]string) {
	t.Helper()
	if got := oidcTagsOf(t, e, arn); !maps.Equal(got, want) {
		t.Fatalf("tags %v, want %v", got, want)
	}
}

// TestOIDCProviderTags: tags written on one replica are listed by another
// started later (a restart reads the same store), sorted by key, keys case
// sensitive; Tag overwrites a value, Untag ignores a key the provider does
// not have, and a repeat of either writes nothing. A tag change keeps the
// URL, UID, client ids, thumbprints and creation time and moves the
// generation. An ARN differing only in case (another issuer), an unknown
// provider and another account's ARN are NoSuchEntity and change nothing,
// and another project's provider of the same URL is never touched. On both
// store backends.
func TestOIDCProviderTags(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			writer := newEnvOn(t, b, &now)
			seedOIDC(t, writer, updateURL, []string{"app"}, thumbprints(2))
			if _, err := writer.api.CreateOpenIDConnectProvider(t.Context(), "beta", updateURL, []string{"app"}, nil,
				nil); err != nil {
				t.Fatal(err)
			}
			key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)
			before := storedOIDC(t, b, key)

			err := writer.api.TagOpenIDConnectProvider(t.Context(), proj, arn,
				[]*iamv1.Tag{samlTag("team", "b"), samlTag("Env", "prod"), samlTag("env", "")})
			if err != nil {
				t.Fatal(err)
			}
			after := storedOIDC(t, b, key)
			p := after.Object
			if p.UID != before.Object.UID || p.URL != before.Object.URL || !p.Created.Equal(before.Object.Created) ||
				!slices.Equal(p.ClientIDs, before.Object.ClientIDs) ||
				!slices.Equal(p.Thumbprints, before.Object.Thumbprints) || p.Generation != before.Object.Generation+1 {
				t.Fatalf("stored after tag: %+v, want URL, UID, lists and creation kept, generation moved", p)
			}
			tagged := map[string]string{"team": "b", "Env": "prod", "env": ""}
			wantOIDCTags(t, newEnvOn(t, b, &now), arn, tagged)

			if err := writer.api.TagOpenIDConnectProvider(t.Context(), proj, arn,
				[]*iamv1.Tag{samlTag("Env", "prod")}); err != nil {
				t.Fatalf("repeat tag: %v", err)
			}
			if v := storedOIDC(t, b, key).Version; v != after.Version {
				t.Fatalf("a repeat tag wrote the provider: version %s, want %s", v, after.Version)
			}

			if err := writer.api.UntagOpenIDConnectProvider(t.Context(), proj, arn, []string{"Env", "none"}); err != nil {
				t.Fatal(err)
			}
			delete(tagged, "Env")
			wantOIDCTags(t, newEnvOn(t, b, &now), arn, tagged)
			untagged := storedOIDC(t, b, key).Version
			if err := writer.api.UntagOpenIDConnectProvider(t.Context(), proj, arn, []string{"Env", "none"}); err != nil {
				t.Fatalf("repeat untag: %v", err)
			}
			if v := storedOIDC(t, b, key).Version; v != untagged {
				t.Fatalf("a repeat untag wrote the provider: version %s, want %s", v, untagged)
			}
			if err := writer.api.UntagOpenIDConnectProvider(t.Context(), proj, arn, []string{"team", "env"}); err != nil {
				t.Fatal(err)
			}
			page, err := newEnvOn(t, b, &now).api.ListOpenIDConnectProviderTags(t.Context(), proj, arn, "", 0)
			if err != nil || len(page.Tags) != 0 || page.IsTruncated || page.Marker != "" {
				t.Fatalf("untagged provider: %+v %v, want an empty complete page", page, err)
			}

			last := storedOIDC(t, b, key).Version
			for _, other := range []string{
				oidcARN(proj, strings.ToLower(updateURL)), oidcARN(proj, "https://unknown.test"), oidcARN("beta", updateURL),
			} {
				err := writer.api.TagOpenIDConnectProvider(t.Context(), proj, other, []*iamv1.Tag{samlTag("k", "v")})
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
				err = writer.api.UntagOpenIDConnectProvider(t.Context(), proj, other, []string{"k"})
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
				_, err = writer.api.ListOpenIDConnectProviderTags(t.Context(), proj, other, "", 0)
				wantAWS(t, err, codes.NotFound, "NoSuchEntity")
			}
			if v := storedOIDC(t, b, key).Version; v != last {
				t.Fatal("a NoSuchEntity tag call wrote the provider")
			}
			oidcGone(t, b, strings.ToLower(updateURL))
			beta, err := store.Get[iam.OIDCProvider](t.Context(), store.Scoped(b, "beta"), key)
			if err != nil || len(beta.Object.Tags) != 0 || beta.Object.Generation != 1 {
				t.Fatalf("another project's provider: %+v %v, want untouched", beta.Object, err)
			}
		})
	}
}

// TestOIDCProviderTagLimits: a provider keeps at most 50 tags: tags up to
// 50 are stored, one more is LimitExceeded and writes nothing, an
// overwrite at 50 succeeds, and a key repeated within one request keeps
// its last value and counts once.
func TestOIDCProviderTagLimits(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	createOIDC(t, e, proj, updateURL)
	key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)
	var tags []*iamv1.Tag
	want := map[string]string{}
	for i := range iam.MaxOIDCProviderTags - 1 {
		k := fmt.Sprintf("k%02d", i)
		tags = append(tags, samlTag(k, "v"))
		want[k] = "v"
	}
	if err := e.api.TagOpenIDConnectProvider(t.Context(), proj, arn, tags); err != nil {
		t.Fatal(err)
	}
	repeated := []*iamv1.Tag{samlTag("last", "1"), samlTag("last", "2"), samlTag("last", "3")}
	if err := e.api.TagOpenIDConnectProvider(t.Context(), proj, arn, repeated); err != nil {
		t.Fatalf("the 50th tag repeated in one request: %v", err)
	}
	want["last"] = "3"
	wantOIDCTags(t, e, arn, want)

	full := storedOIDC(t, b, key).Version
	err := e.api.TagOpenIDConnectProvider(t.Context(), proj, arn, []*iamv1.Tag{samlTag("k00", "w"), samlTag("new", "v")})
	wantAWS(t, err, codes.ResourceExhausted, "LimitExceeded")
	if v := storedOIDC(t, b, key).Version; v != full {
		t.Fatal("a LimitExceeded tag wrote the provider")
	}
	if err := e.api.TagOpenIDConnectProvider(t.Context(), proj, arn, []*iamv1.Tag{samlTag("k00", "w")}); err != nil {
		t.Fatalf("overwrite at 50 tags: %v", err)
	}
	want["k00"] = "w"
	wantOIDCTags(t, e, arn, want)

	long := []*iamv1.Tag{samlTag(strings.Repeat("k", iam.MaxTagKeyLen), strings.Repeat("v", iam.MaxTagValueLen))}
	if err := e.api.UntagOpenIDConnectProvider(t.Context(), proj, arn, []string{"k01"}); err != nil {
		t.Fatal(err)
	}
	if err := e.api.TagOpenIDConnectProvider(t.Context(), proj, arn, long); err != nil {
		t.Fatalf("a key of %d and a value of %d characters: %v", iam.MaxTagKeyLen, iam.MaxTagValueLen, err)
	}
}

// TestOIDCProviderTagsPages: MaxItems bounds every page, a truncated page
// carries a marker, and the pages together hold every tag once, in key
// order; 0 is the AWS default of 100, which holds all 50. A tag added or
// removed between pages shifts nothing already listed. On both store
// backends.
func TestOIDCProviderTagsPages(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			e := newEnvOn(t, b, &now)
			createOIDC(t, e, proj, updateURL)
			arn := oidcARN(proj, updateURL)
			var tags []*iamv1.Tag
			for i := range iam.MaxOIDCProviderTags {
				tags = append(tags, samlTag(fmt.Sprintf("k%02d", i), fmt.Sprint(i)))
			}
			if err := e.api.TagOpenIDConnectProvider(t.Context(), proj, arn, tags); err != nil {
				t.Fatal(err)
			}
			if got := oidcTagsOf(t, e, arn); len(got) != iam.MaxOIDCProviderTags {
				t.Fatalf("default page holds %d tags, want %d", len(got), iam.MaxOIDCProviderTags)
			}
			for _, n := range []int{1, 7, 49, 50} {
				var keys []string
				marker := ""
				for pages := 1; ; pages++ {
					page, err := e.api.ListOpenIDConnectProviderTags(t.Context(), proj, arn, marker, n)
					if err != nil {
						t.Fatal(err)
					}
					if len(page.Tags) > n || (page.IsTruncated && page.Marker == "") || pages > iam.MaxOIDCProviderTags {
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
				if len(keys) != iam.MaxOIDCProviderTags {
					t.Fatalf("pages of %d: %d tags, want %d", n, len(keys), iam.MaxOIDCProviderTags)
				}
				for i, k := range keys {
					if k != fmt.Sprintf("k%02d", i) {
						t.Fatalf("pages of %d: key %d is %q", n, i, k)
					}
				}
			}

			first, err := e.api.ListOpenIDConnectProviderTags(t.Context(), proj, arn, "", 2)
			if err != nil {
				t.Fatal(err)
			}
			if err := e.api.UntagOpenIDConnectProvider(t.Context(), proj, arn, []string{"k00", "k02"}); err != nil {
				t.Fatal(err)
			}
			if err := e.api.TagOpenIDConnectProvider(t.Context(), proj, arn, []*iamv1.Tag{samlTag("a", "early")}); err != nil {
				t.Fatal(err)
			}
			second, err := e.api.ListOpenIDConnectProviderTags(t.Context(), proj, arn, first.Marker, 2)
			if err != nil || len(second.Tags) != 2 || second.Tags[0].Key != "k03" || second.Tags[1].Key != "k04" {
				t.Fatalf("page after changes: %+v %v, want k03 and k04", second.Tags, err)
			}
		})
	}
}

// TestOIDCProviderTagsConcurrent: tags of different keys written at once
// on two replicas are all kept, and racing equal tags all succeed and
// write once. On both store backends.
func TestOIDCProviderTagsConcurrent(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			b := bk.open()
			now := time.Now().UTC()
			replicas := []*env{newEnvOn(t, b, &now), newEnvOn(t, b, &now)}
			createOIDC(t, replicas[0], proj, updateURL)
			key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)
			// At most maxDeleteAttempts writers: each lost race is another
			// writer's success, so every one commits within its attempts.
			errs := make([]error, 8)
			var wg sync.WaitGroup
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.TagOpenIDConnectProvider(t.Context(), proj, arn,
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
			wantOIDCTags(t, replicas[0], arn, want)

			gen := storedOIDC(t, b, key).Object.Generation
			for i := range errs {
				wg.Go(func() {
					errs[i] = replicas[i%2].api.TagOpenIDConnectProvider(t.Context(), proj, arn,
						[]*iamv1.Tag{samlTag("same", "v")})
				})
			}
			wg.Wait()
			for i, err := range errs {
				if err != nil {
					t.Fatalf("equal tag %d: %v", i, err)
				}
			}
			if g := storedOIDC(t, b, key).Object.Generation; g != gen+1 {
				t.Fatalf("generation %d after racing equal tags, want %d", g, gen+1)
			}
		})
	}
}

// TestOIDCProviderTagsStaleRead: a provider written after it was read is
// read again and then tagged or untagged, keeping the other writer's
// change; one that keeps changing is ConcurrentModification and keeps its
// tags. On both store backends.
func TestOIDCProviderTagsStaleRead(t *testing.T) {
	for _, bk := range renameBackends {
		t.Run(bk.name, func(t *testing.T) {
			inner := bk.open()
			now := time.Now().UTC()
			seedOIDC(t, newEnvOn(t, inner, &now), updateURL, []string{"app"}, nil)
			key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)

			b := &changingOIDCBeforeUpdate{Backend: inner, n: 1, t: t}
			if err := newEnvOn(t, b, &now).api.TagOpenIDConnectProvider(t.Context(), proj, arn,
				[]*iamv1.Tag{samlTag("mine", "v")}); err != nil {
				t.Fatalf("tag after one concurrent write: %v", err)
			}
			want := map[string]string{"team": "a", "writer": "other", "mine": "v"}
			if got := storedOIDC(t, inner, key).Object.Tags; !maps.Equal(got, want) {
				t.Fatalf("stored tags %v, want the other writer's and this one", got)
			}
			b = &changingOIDCBeforeUpdate{Backend: inner, n: 1, t: t}
			if err := newEnvOn(t, b, &now).api.UntagOpenIDConnectProvider(t.Context(), proj, arn,
				[]string{"writer"}); err != nil {
				t.Fatalf("untag after one concurrent write: %v", err)
			}
			if got := storedOIDC(t, inner, key).Object.Tags; !maps.Equal(got, map[string]string{"team": "a"}) {
				t.Fatalf("stored tags %v, want team only", got)
			}

			b = &changingOIDCBeforeUpdate{Backend: inner, n: 1 << 30, t: t}
			err := newEnvOn(t, b, &now).api.TagOpenIDConnectProvider(t.Context(), proj, arn,
				[]*iamv1.Tag{samlTag("lost", "v")})
			wantAWS(t, err, codes.Aborted, "ConcurrentModification")
			if _, ok := storedOIDC(t, inner, key).Object.Tags["lost"]; ok {
				t.Fatal("a ConcurrentModification tag was stored")
			}
		})
	}
}

// TestOIDCProviderTagsCanceled: a canceled tag or untag writes nothing,
// and the same request afterwards applies.
func TestOIDCProviderTagsCanceled(t *testing.T) {
	b := memstore.New()
	now := time.Now().UTC()
	e := newEnvOn(t, b, &now)
	createOIDC(t, e, proj, updateURL)
	key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	tags := []*iamv1.Tag{samlTag("k", "v")}
	if err := e.api.TagOpenIDConnectProvider(canceled, proj, arn, tags); err == nil {
		t.Fatal("a canceled tag succeeded")
	}
	if len(storedOIDC(t, b, key).Object.Tags) != 0 {
		t.Fatal("a canceled tag wrote the provider")
	}
	if err := e.api.TagOpenIDConnectProvider(t.Context(), proj, arn, tags); err != nil {
		t.Fatalf("the same tag afterwards: %v", err)
	}
	if err := e.api.UntagOpenIDConnectProvider(canceled, proj, arn, []string{"k"}); err == nil {
		t.Fatal("a canceled untag succeeded")
	}
	if len(storedOIDC(t, b, key).Object.Tags) != 1 {
		t.Fatal("a canceled untag wrote the provider")
	}
	if err := e.api.UntagOpenIDConnectProvider(t.Context(), proj, arn, []string{"k"}); err != nil {
		t.Fatalf("the same untag afterwards: %v", err)
	}
	if len(storedOIDC(t, b, key).Object.Tags) != 0 {
		t.Fatal("the untag did not remove the tag")
	}
}

// TestOIDCProviderTagErrors: request faults are answered before any store
// access (the store here fails every read), never echoing the ARN: a bad
// project, a bad ARN length, no or more than 50 tags or keys and a bad
// maxItems or marker character are ValidationError; an ARN that is not an
// OIDC provider ARN, a tag or key outside the AWS tag rules and a marker
// this service did not issue are InvalidInput; another account's ARN is
// NoSuchEntity. A store failure is ServiceFailure or ServiceUnavailable,
// as is a stored provider that no longer validates. None writes.
func TestOIDCProviderTagErrors(t *testing.T) {
	inner := memstore.New()
	now := time.Now().UTC()
	createOIDC(t, newEnvOn(t, inner, &now), proj, updateURL)
	key, arn := iam.OIDCProviderKey(updateURL), oidcARN(proj, updateURL)
	stored := storedOIDC(t, inner, key).Version
	down := newEnvOn(t, failingGet{Backend: inner, k: iam.KindOIDCProvider, err: store.ErrUnavailable}, &now)
	const canary = "CANARY"
	prefix := "arn:vws:iam::" + proj + ":oidc-provider/"
	ok := []*iamv1.Tag{samlTag("k", "v")}
	var tooMany []*iamv1.Tag
	var tooManyKeys []string
	for i := range iam.MaxOIDCProviderTags + 1 {
		tooMany = append(tooMany, samlTag(fmt.Sprint(i), "v"))
		tooManyKeys = append(tooManyKeys, fmt.Sprint(i))
	}
	argCases := []struct {
		name, pid, arn string
		tags           []*iamv1.Tag
		keys           []string // nil: the case is not one of Untag
		list           bool     // the case is one of ListOpenIDConnectProviderTags too
		code           codes.Code
		aws            string
	}{
		{"bad project", "Bad Project", arn, ok, []string{"k"}, true, codes.InvalidArgument, "ValidationError"},
		{"short ARN", proj, strings.Repeat("a", 19), ok, []string{"k"}, true, codes.InvalidArgument, "ValidationError"},
		{
			"ARN of 2049 characters", proj, prefix + strings.Repeat("a", 2049-len(prefix)), ok,
			[]string{"k"},
			true,
			codes.InvalidArgument, "ValidationError",
		},
		{
			"SAML provider ARN", proj, "arn:vws:iam::" + proj + ":saml-provider/" + canary, ok,
			[]string{"k"},
			true,
			codes.InvalidArgument, "InvalidInput",
		},
		{
			"host with a port", proj, prefix + canary + ".test:443", ok,
			[]string{"k"},
			true,
			codes.InvalidArgument, "InvalidInput",
		},
		{"another account", proj, oidcARN("beta", updateURL), ok, []string{"k"}, true, codes.NotFound, "NoSuchEntity"},
		{"none", proj, arn, nil, []string{}, false, codes.InvalidArgument, "ValidationError"},
		{"51", proj, arn, tooMany, tooManyKeys, false, codes.InvalidArgument, "ValidationError"},
		{"empty key", proj, arn, []*iamv1.Tag{samlTag("", "v")}, []string{""}, false, codes.InvalidArgument, "InvalidInput"},
		{
			"aws: prefix", proj, arn,
			[]*iamv1.Tag{samlTag("aws:k", "v")},
			[]string{"aws:k"},
			false,
			codes.InvalidArgument, "InvalidInput",
		},
		{
			"key of 129", proj, arn,
			[]*iamv1.Tag{samlTag(strings.Repeat("k", 129), "v")},
			[]string{strings.Repeat("k", 129)},
			false,
			codes.InvalidArgument, "InvalidInput",
		},
		{
			"bad key character", proj, arn,
			[]*iamv1.Tag{samlTag("k!", "v")},
			[]string{"k!"},
			false,
			codes.InvalidArgument, "InvalidInput",
		},
		{
			"value of 257", proj, arn,
			[]*iamv1.Tag{samlTag("k", strings.Repeat("v", 257))},
			nil, false,
			codes.InvalidArgument, "InvalidInput",
		},
		{"store down", proj, arn, ok, []string{"k"}, true, codes.Unavailable, "ServiceUnavailable"},
	}
	for _, c := range argCases {
		t.Run(c.name, func(t *testing.T) {
			errs := []error{down.api.TagOpenIDConnectProvider(t.Context(), c.pid, c.arn, c.tags)}
			if c.keys != nil {
				errs = append(errs, down.api.UntagOpenIDConnectProvider(t.Context(), c.pid, c.arn, c.keys))
			}
			if c.list {
				_, err := down.api.ListOpenIDConnectProviderTags(t.Context(), c.pid, c.arn, "", 0)
				errs = append(errs, err)
			}
			for i, err := range errs {
				wantAWS(t, err, c.code, c.aws)
				if strings.Contains(status.Convert(err).Message(), canary) {
					t.Fatalf("call %d: message carries the ARN: %q", i, status.Convert(err).Message())
				}
			}
			if v := storedOIDC(t, inner, key).Version; v != stored {
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
			_, err := down.api.ListOpenIDConnectProviderTags(t.Context(), proj, arn, c.marker, c.maxItems)
			wantAWS(t, err, c.code, c.aws)
		})
	}
	if _, err := newEnvOn(t, inner, &now).api.ListOpenIDConnectProviderTags(t.Context(), proj, arn, "", 1000); err != nil {
		t.Fatalf("maxItems 1000: %v", err)
	}

	boom := errors.New("backend down")
	failures := []struct {
		name string
		b    store.Backend
		code codes.Code
		aws  string
		list bool
	}{
		{
			"read fails",
			failingGet{Backend: inner, k: iam.KindOIDCProvider, err: boom},
			codes.Internal, "ServiceFailure", true,
		},
		{
			"write fails",
			failingUpdate{Backend: inner, k: iam.KindOIDCProvider, err: boom},
			codes.Internal, "ServiceFailure", false,
		},
		{
			"write unavailable",
			failingUpdate{Backend: inner, k: iam.KindOIDCProvider, err: store.ErrUnavailable},
			codes.Unavailable, "ServiceUnavailable", false,
		},
		{"stored provider does not validate", corruptOIDCGet{Backend: inner}, codes.Internal, "ServiceFailure", false},
	}
	for _, c := range failures {
		t.Run(c.name, func(t *testing.T) {
			e := newEnvOn(t, c.b, &now)
			wantAWS(t, e.api.TagOpenIDConnectProvider(t.Context(), proj, arn, ok), c.code, c.aws)
			if c.list {
				_, err := e.api.ListOpenIDConnectProviderTags(t.Context(), proj, arn, "", 0)
				wantAWS(t, err, c.code, c.aws)
			}
			if v := storedOIDC(t, inner, key).Version; v != stored {
				t.Fatal("a failed tag call wrote the provider")
			}
		})
	}
}
