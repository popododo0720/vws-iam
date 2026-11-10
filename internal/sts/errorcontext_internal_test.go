package sts

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/store"
)

func TestOperationContextPreservesClientFaults(t *testing.T) {
	for _, fault := range clientFaults {
		original := fmt.Errorf("%w: original client message", fault)
		err := error(original)
		wrapOperationError("AssumeRoleWithSAML", &err)
		if err.Error() != original.Error() || !errors.Is(err, fault) {
			t.Fatalf("client fault changed: %v", err)
		}
	}
	for _, cause := range []error{store.ErrUnavailable, errors.New("backend unavailable")} {
		err := cause
		wrapOperationError("Resolve", &err)
		if !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "sts.Resolve: ") {
			t.Fatalf("operation or cause lost: %v", err)
		}
	}
	var err error
	wrapOperationError("Resolve", &err)
	if err != nil {
		t.Fatal("success became a failure")
	}
}
