package grpcapi

import (
	"context"
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonv1 "github.com/popododo0720/vws-proto/gen/go/vws/common/v1"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/policy"
	"github.com/popododo0720/vws-iam/internal/store"
)

// MaxAttachedPolicies is the AWS limit of managed policies per entity.
const MaxAttachedPolicies = 10

func ts(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func ready(gen int64) *commonv1.ObservedState {
	return &commonv1.ObservedState{State: commonv1.ReconciliationState_RECONCILIATION_STATE_READY, Generation: gen}
}

// page returns one page of items (already ordered by key) after the token.
func page[T any](items []T, key func(T) string, size int32, token string) ([]T, string, error) {
	switch {
	case size <= 0:
		size = 50
	case size > 1000:
		size = 1000
	}
	start := 0
	if token != "" {
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return nil, "", invalidSpec("page_token is not valid")
		}
		after := string(raw)
		start = sort.Search(len(items), func(i int) bool { return store.Fold(key(items[i])) > after })
	}
	end := min(start+int(size), len(items))
	next := ""
	if end < len(items) {
		next = base64.RawURLEncoding.EncodeToString([]byte(store.Fold(key(items[end-1]))))
	}
	return items[start:end], next, nil
}

// paths resolves an update mask against the allowed paths. An empty mask
// is "spec,labels". "spec" expands to every allowed spec.* path.
func paths(mask *fieldmaskpb.FieldMask, allowed ...string) (map[string]bool, error) {
	ps := mask.GetPaths()
	if len(ps) == 0 {
		ps = []string{"spec", "labels"}
	}
	ok := map[string]bool{"labels": true}
	for _, a := range allowed {
		ok[a] = true
	}
	out := map[string]bool{}
	for _, p := range ps {
		switch {
		case p == "spec":
			for _, a := range allowed {
				out[a] = true
			}
		case ok[p]:
			out[p] = true
		default:
			return nil, invalidSpec("update_mask path " + quote(p) + " cannot be updated")
		}
	}
	return out, nil
}

func checkEtag(etag, version string) error {
	if etag != "" && etag != version {
		return fail(codes.Aborted, "ETAG_MISMATCH", "ConcurrentModification", "etag does not match the stored resource")
	}
	return nil
}

// attachedARNs resolves policy resource names of project to ARNs.
func (p project) attachedARNs(ctx context.Context, names []string) ([]string, error) {
	if len(names) > MaxAttachedPolicies {
		return nil, quota("at most 10 managed policies may be attached")
	}
	out := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, n := range names {
		proj, id, err := child(n, "policies")
		if err != nil {
			return nil, err
		}
		if proj != p.id {
			return nil, invalidSpec("policy " + quote(n) + " is in another project")
		}
		pol, err := store.Get[iam.Policy](ctx, p.b, id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("policy " + quote(n) + " does not exist")
		}
		if err != nil {
			return nil, err
		}
		arn := iam.PolicyARN(p.id, pol.Object)
		if seen[arn] {
			return nil, invalidSpec("policy " + quote(n) + " is attached twice")
		}
		seen[arn] = true
		out = append(out, arn)
	}
	return out, nil
}

func (p project) policyNames(arns []string) []string {
	out := make([]string, 0, len(arns))
	for _, a := range arns {
		out = append(out, name(p.id, "policies", a[strings.LastIndex(a, "/")+1:]))
	}
	return out
}

func checkInline(m map[string]string) error {
	for k, doc := range m {
		if !iam.ValidName(k) {
			return invalidSpec("inline policy name " + quote(k))
		}
		if _, err := policy.ParseIdentity(doc); err != nil {
			return err
		}
	}
	return nil
}

func labels(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func defaultPath(p string) string {
	if p == "" {
		return "/"
	}
	return p
}
