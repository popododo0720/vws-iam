package grpcapi

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"cloud.google.com/go/longrunning/autogen/longrunningpb"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// once names an update by its request_id inside the object it changes
// (#50). Its token is written in the same compare-and-swap as the change,
// so a duplicate that races its first delivery finds it and is not applied
// again. The operation record that done writes after the change only
// answers later replays. The zero once (no request_id) matches nothing.
type once struct{ op, fp string }

func newOnce(project, method, requestID string, req proto.Message) once {
	if requestID == "" {
		return once{}
	}
	return once{op: opID(project, method, requestID), fp: fingerprint(req)}
}

// check is errApplied when m records this request, and
// IdempotentParameterMismatch, as replay answers, when m records its
// request_id with another request.
func (o once) check(m iam.Meta) error {
	if o.op == "" {
		return nil
	}
	for _, t := range m.Requests {
		op, fp, _ := strings.Cut(t, ".")
		if op != o.op {
			continue
		}
		if fp != o.fp {
			return idempotencyConflict()
		}
		return errApplied
	}
	return nil
}

// token is what record stores; empty without a request_id.
func (o once) token() string {
	if o.op == "" {
		return ""
	}
	return o.op + "." + o.fp
}

// record adds the token to m, dropping the oldest beyond iam.MaxRequests.
func (o once) record(m *iam.Meta) {
	if o.op == "" {
		return
	}
	m.Requests = append(m.Requests, o.token())
	if n := len(m.Requests) - iam.MaxRequests; n > 0 {
		m.Requests = slices.Delete(m.Requests, 0, n)
	}
}

func idempotencyConflict() error {
	return fail(
		codes.Aborted,
		"IDEMPOTENCY_CONFLICT",
		"IdempotentParameterMismatch",
		"request_id was used with a different request",
	)
}

// appliedWait bounds how long applied waits for the operation record of an
// earlier delivery.
const appliedWait = 500 * time.Millisecond

// applied answers a request whose change an earlier delivery already made
// (errApplied): with the operation that delivery records, once it lands.
// Nil means none landed within appliedWait, so that delivery stopped after
// its change; the caller then answers from the stored state, and done
// records that answer for later replays.
func (s *Server) applied(
	ctx context.Context,
	project, method, requestID string,
	req proto.Message,
) (*longrunningpb.Operation, error) {
	delay := 5 * time.Millisecond
	deadline := time.Now().Add(appliedWait)
	for {
		op, err := s.replay(ctx, project, method, requestID, req)
		if op != nil || err != nil || !time.Now().Before(deadline) {
			return op, err
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for the operation of an earlier delivery: %w", ctx.Err())
		case <-time.After(delay):
		}
		delay = min(2*delay, 100*time.Millisecond)
	}
}
