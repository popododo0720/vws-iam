package grpcapi

import (
	"context"
	"errors"
	"testing"
)

func TestBoundaryConflictWaitCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := waitBoundaryConflict(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("retry wait after cancellation = %v, want context cancellation", err)
	}
}
