package authz

import (
	"context"
	"errors"
	"fmt"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

func (a *Authorizer) userBoundary(ctx context.Context, p Principal) ([]policy.Named, error) {
	u, err := store.Get[iam.User](ctx, a.b, p.Name)
	if errors.Is(err, store.ErrNotFound) || err == nil && p.ID != "" && u.Object.ID != p.ID {
		return nil, fmt.Errorf("user boundary: %w", ErrNoSuchEntity)
	}
	if err != nil {
		return nil, fmt.Errorf("read user boundary: %w", err)
	}
	if u.Object.PermissionsBoundary == "" {
		return nil, nil
	}
	b, err := a.managed(ctx, u.Object.PermissionsBoundary)
	if err != nil {
		return nil, fmt.Errorf("read user permissions boundary: %w", err)
	}
	return []policy.Named{b}, nil
}
