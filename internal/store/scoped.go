package store

import (
	"context"
	"strings"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// scoped prefixes every key with a project, so one Backend holds every
// project (AWS account) and a project only sees its own objects.
type scoped struct {
	b      Backend
	prefix string
}

// Scoped returns the view of b for project. The project must be valid.
func Scoped(b Backend, project string) Backend {
	return scoped{b: b, prefix: project + "/"}
}

func (s scoped) Create(ctx context.Context, kind iam.Kind, key string, spec []byte) (string, error) {
	return s.b.Create(ctx, kind, s.prefix+key, spec)
}

func (s scoped) Update(ctx context.Context, kind iam.Kind, key string, spec []byte, version string) (string, error) {
	return s.b.Update(ctx, kind, s.prefix+key, spec, version)
}

func (s scoped) Get(ctx context.Context, kind iam.Kind, key string) (Entry, error) {
	e, err := s.b.Get(ctx, kind, s.prefix+key)
	e.Key = strings.TrimPrefix(e.Key, s.prefix)
	return e, err
}

func (s scoped) List(ctx context.Context, kind iam.Kind) ([]Entry, error) {
	all, err := s.b.List(ctx, kind)
	if err != nil {
		return nil, err
	}
	p := Fold(s.prefix)
	out := all[:0]
	for _, e := range all {
		if strings.HasPrefix(Fold(e.Key), p) {
			e.Key = e.Key[len(s.prefix):]
			out = append(out, e)
		}
	}
	return out, nil
}

func (s scoped) Delete(ctx context.Context, kind iam.Kind, key, version string) error {
	return s.b.Delete(ctx, kind, s.prefix+key, version)
}
