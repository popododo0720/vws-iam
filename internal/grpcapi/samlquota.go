package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

func samlProvidersPerAccountExceeded() error {
	return quota("Cannot exceed quota for SAMLProvidersPerAccount: " + strconv.Itoa(iam.MaxSAMLProvidersPerAccount))
}

// storeSAMLProvider stores sp, a new provider of project p, unless the
// project already has iam.MaxSAMLProvidersPerAccount providers
// (LimitExceeded) or a provider of its name in any case
// (EntityAlreadyExists). A hold lost to another writer is retried with
// backoff; one that keeps losing is ConcurrentModification.
func (p project) storeSAMLProvider(ctx context.Context, sp iam.SAMLProvider) error {
	for attempt := 0; ; attempt++ {
		err := p.storeSAMLProviderLocked(ctx, sp)
		if !errors.Is(err, errLockLost) {
			return err
		}
		if berr := backoff(ctx, attempt); berr != nil {
			return berr
		}
	}
}

// storeSAMLProviderLocked counts and commits sp under one hold of the
// project's quota lock (the lock member adds and key creates take). The
// store has no conditional create, so the provider is first created
// Pending, which no read sees and no count includes, and is then made
// active by store.UpdateIf on the lock at the version this hold took. A
// writer whose lease ran out before that commit cannot make its provider
// active, because the next holder moved the lock, so the active providers
// never pass the quota. A pending provider left by a writer that died or
// lost its hold is taken over by the next create of its name, under that
// create's own count. errLockLost asks for a new hold.
func (p project) storeSAMLProviderLocked(ctx context.Context, sp iam.SAMLProvider) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("SAML provider %q: %w", sp.Name, err) // the caller is gone; write nothing
	}
	pre, unlock, err := p.lockMembership(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	cur, err := store.Get[iam.SAMLProvider](ctx, p.b, sp.Name)
	found := err == nil
	switch {
	case found && !cur.Object.Pending && cur.Object.UID == sp.UID:
		return nil // an earlier hold of this request committed it
	case found && !cur.Object.Pending:
		return alreadyExists("Provider with name " + sp.Name + " already exists.")
	case !found && !errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("get SAML provider %q: %w", sp.Name, err)
	}
	all, err := store.List[iam.SAMLProvider](ctx, p.b)
	if err != nil {
		return fmt.Errorf("list SAML providers: %w", err)
	}
	active := 0
	for _, v := range all {
		if !v.Object.Pending {
			active++
		}
	}
	if active >= iam.MaxSAMLProvidersPerAccount {
		return samlProvidersPerAccountExceeded()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("SAML provider %q: %w", sp.Name, err)
	}
	version := cur.Version
	if !found {
		pending := sp
		pending.Pending = true
		version, err = store.Create(ctx, p.b, pending)
		if errors.Is(err, store.ErrExists) {
			return errLockLost // a writer without the hold made it in between; read it again
		}
		if err != nil {
			return fmt.Errorf("create pending SAML provider %q: %w", sp.Name, err)
		}
	}
	_, err = store.UpdateIf(ctx, p.b, sp, version, pre)
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		return errLockLost
	}
	if err != nil {
		return fmt.Errorf("activate SAML provider %q: %w", sp.Name, err)
	}
	return nil
}
