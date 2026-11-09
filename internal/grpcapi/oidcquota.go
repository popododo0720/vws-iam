package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func oidcProvidersPerAccountExceeded() error {
	return quota("Cannot exceed quota for OpenIdConnectProvidersPerAccount: " +
		strconv.Itoa(iam.MaxOIDCProvidersPerAccount))
}

// storeOIDCProvider stores op, a new provider of project p, unless the
// project already has iam.MaxOIDCProvidersPerAccount providers
// (LimitExceeded) or a provider of its URL (EntityAlreadyExists). A hold
// lost to another writer is retried with backoff.
func (p project) storeOIDCProvider(ctx context.Context, op iam.OIDCProvider) error {
	for attempt := 0; ; attempt++ {
		err := p.storeOIDCProviderLocked(ctx, op)
		if !errors.Is(err, errLockLost) {
			return err
		}
		if berr := backoff(ctx, attempt); berr != nil {
			return berr
		}
	}
}

// storeOIDCProviderLocked counts and commits op under one hold of the
// project's quota lock, as storeSAMLProviderLocked does for SAML
// providers: the provider is created Pending, which no read sees and no
// count includes, and made active by store.UpdateIf on the lock at the
// version this hold took, so a writer whose lease ran out cannot commit
// and the active providers never pass the quota. A pending provider left
// by a writer that died or lost its hold is taken over by the next create
// of its URL, under that create's own count. errLockLost asks for a new
// hold.
func (p project) storeOIDCProviderLocked(ctx context.Context, op iam.OIDCProvider) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("OpenID Connect provider: %w", err) // the caller is gone; write nothing
	}
	pre, unlock, err := p.lockMembership(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	key := op.Key()
	cur, err := store.Get[iam.OIDCProvider](ctx, p.b, key)
	found := err == nil
	switch {
	case found && !cur.Object.Pending && cur.Object.UID == op.UID:
		return nil // an earlier hold of this request committed it
	case found && !cur.Object.Pending:
		return alreadyExists("Provider with url " + op.URL + " already exists.")
	case !found && !errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("get OpenID Connect provider %q: %w", key, err)
	}
	all, err := store.List[iam.OIDCProvider](ctx, p.b)
	if err != nil {
		return fmt.Errorf("list OpenID Connect providers: %w", err)
	}
	active := 0
	for _, v := range all {
		if !v.Object.Pending {
			active++
		}
	}
	if active >= iam.MaxOIDCProvidersPerAccount {
		return oidcProvidersPerAccountExceeded()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("OpenID Connect provider %q: %w", key, err)
	}
	version := cur.Version
	if !found {
		pending := op
		pending.Pending = true
		version, err = store.Create(ctx, p.b, pending)
		if errors.Is(err, store.ErrExists) {
			return errLockLost // a writer without the hold made it in between; read it again
		}
		if err != nil {
			return fmt.Errorf("create pending OpenID Connect provider %q: %w", key, err)
		}
	}
	_, err = store.UpdateIf(ctx, p.b, op, version, pre)
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		return errLockLost
	}
	if err != nil {
		return fmt.Errorf("activate OpenID Connect provider %q: %w", key, err)
	}
	return nil
}
