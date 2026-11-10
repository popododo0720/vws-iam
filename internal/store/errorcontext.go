package store

import (
	"fmt"

	"github.com/popododo0720/vws-iam/internal/iam"
)

func addErrorContext(operation string, kind iam.Kind, err *error) {
	*err = contextualError(operation, kind, *err)
}

func contextualError(operation string, kind iam.Kind, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("store %s %s: %w", operation, kind, err)
}
