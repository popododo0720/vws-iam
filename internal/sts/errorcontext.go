package sts

import (
	"context"
	"errors"
	"fmt"

	"github.com/popododo0720/vws-iam/internal/authz"
	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

// Client faults already carry their wire text. Only infrastructure failures
// gain an operation prefix; no request value is included in that prefix.
var clientFaults = []error{
	ErrAccessDenied, ErrExpired, ErrInvalidToken, ErrInvalidRequest, ErrThrottling,
	ErrInvalidAuthorizationMessage, ErrInvalidIdentityToken, ErrIDPRejectedClaim,
	ErrIDPCommunication, ErrPackedPolicyTooLarge, ErrNoSuchAccessKey,
	policy.ErrMalformed, authz.ErrNoSuchEntity, iam.ErrInvalid,
	store.ErrNotFound, store.ErrExists, store.ErrConflict, store.ErrRenaming,
	context.Canceled, context.DeadlineExceeded,
}

func wrapOperationError(operation string, err *error) {
	if *err == nil {
		return
	}
	for _, fault := range clientFaults {
		if errors.Is(*err, fault) {
			return
		}
	}
	*err = fmt.Errorf("sts.%s: %w", operation, *err)
}
