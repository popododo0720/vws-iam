package kubestore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// Conditional writes (UpdateIf, DeleteIf).
//
// Kubernetes has no transaction over two objects, so a write to object K
// that must commit only while object P is still at version V is
// serialized through K's resourceVersion:
//
//  1. Fence: P is updated at resourceVersion V with an annotation
//     fencePrefix+id = {kind, name, version} naming K and the version kv
//     the writer read K at. This compare-and-swap is the check of the
//     precondition: it fails if P moved since it was read.
//  2. Write: K is updated or deleted at resourceVersion kv.
//  3. Unfence: the annotation is removed from P (best effort).
//
// Every Update or Delete of P first voids each fence on P by bumping K
// away from kv (an annotation change, so the API server cannot skip it
// as a no-op), and only then writes P at the resourceVersion it read,
// which drops the fences. A fence added after that read changes P's
// resourceVersion, so that write of P fails and is retried on fresh state.
//
// So if a change of P commits, every conditional write fenced on P before
// it either committed on K before the void (it was ordered before the
// change of P, while P still had the checked content) or can no longer
// commit, because K is no longer at kv. A conditional write that fenced
// after the change fails at step 1. Both orders go through etcd's
// compare-and-swap on one object, so the outcome does not depend on
// timing, on replica clocks, or on the writer staying alive: a fence left
// by a crashed writer or a write with an unknown outcome is voided by the
// next change of P. Fence and unfence change P's resourceVersion but not
// its spec.

// fencePrefix starts the annotation of one pending conditional write.
const fencePrefix = Group + "/fence-"

// voidAnno marks an object bumped to void a fence; its value is the
// fence id.
const voidAnno = Group + "/voided-fence"

// fence is the value of a fence annotation: the guarded object and the
// version the conditional write needs it at.
type fence struct {
	Kind    iam.Kind `json:"kind"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
}

// unfenceTimeout bounds step 3 when the caller's context is done.
const unfenceTimeout = 5 * time.Second

// UpdateIf implements store.Backend with a fence on pre's object.
func (s *Store) UpdateIf(
	ctx context.Context, kind iam.Kind, key string, spec []byte, version string, pre store.Pre,
) (string, error) {
	var out string
	err := s.fenced(ctx, kind, key, version, pre, func() error {
		v, err := s.Update(ctx, kind, key, spec, version)
		out = v
		return err
	})
	return out, err
}

// DeleteIf implements store.Backend with a fence on pre's object.
func (s *Store) DeleteIf(ctx context.Context, kind iam.Kind, key, version string, pre store.Pre) error {
	if version == "" {
		return store.ErrNoVersion
	}
	return s.fenced(ctx, kind, key, version, pre, func() error {
		return s.Delete(ctx, kind, key, version)
	})
}

// fenced runs write between a fence on pre's object and its removal. A
// write with an unknown outcome keeps the fence, so the next change of
// pre's object voids that write if it has not landed yet.
func (s *Store) fenced(
	ctx context.Context, kind iam.Kind, key, version string, pre store.Pre, write func() error,
) error {
	id, err := s.fence(ctx, pre, fence{Kind: kind, Name: objectName(key), Version: version})
	if err != nil {
		return err
	}
	err = write()
	if err != nil && !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), unfenceTimeout)
	defer cancel()
	if uerr := s.unfence(uctx, pre, id); uerr != nil && err == nil {
		// The write committed and moved the object off the fenced
		// version, so a fence that stays costs the next change of pre's
		// object one read and voids nothing.
		return nil
	}
	return err
}

// fence records f on pre's object if it is still at pre.Version and
// returns the fence id.
func (s *Store) fence(ctx context.Context, pre store.Pre, f fence) (string, error) {
	u, err := s.get(ctx, pre.Kind, pre.Key)
	if errors.Is(err, store.ErrNotFound) {
		return "", fmt.Errorf("%w: precondition object is gone", store.ErrConflict)
	}
	if err != nil {
		return "", err
	}
	if u.GetResourceVersion() != pre.Version {
		return "", fmt.Errorf("%w: precondition object moved", store.ErrConflict)
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("fence id: %w", err)
	}
	id := hex.EncodeToString(b)
	val, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("fence: %w", err)
	}
	ann := u.GetAnnotations()
	if ann == nil {
		ann = map[string]string{}
	}
	ann[fencePrefix+id] = string(val)
	u.SetAnnotations(ann)
	if err := s.c.Update(ctx, u); err != nil {
		return "", translate(err)
	}
	return id, nil
}

// unfence removes fence id from pre's object. A fence already voided and
// dropped, or an object already gone, is fine.
func (s *Store) unfence(ctx context.Context, pre store.Pre, id string) error {
	for attempt := 0; ; attempt++ {
		u, err := s.get(ctx, pre.Kind, pre.Key)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		ann := u.GetAnnotations()
		if _, ok := ann[fencePrefix+id]; !ok {
			return nil
		}
		delete(ann, fencePrefix+id)
		u.SetAnnotations(ann)
		err = translate(s.c.Update(ctx, u))
		if errors.Is(err, store.ErrConflict) && attempt < 8 {
			continue
		}
		return err
	}
}

// voidFences makes every conditional write fenced on u unable to commit:
// each guarded object still at the fenced version is bumped. A fence that
// cannot be read is an error, so u is not changed past it.
func (s *Store) voidFences(ctx context.Context, u *unstructured.Unstructured) error {
	for k, v := range u.GetAnnotations() {
		id, ok := strings.CutPrefix(k, fencePrefix)
		if !ok {
			continue
		}
		var f fence
		if err := json.Unmarshal([]byte(v), &f); err != nil {
			return fmt.Errorf("fence %s on %s: %w", id, u.GetName(), err)
		}
		if err := s.void(ctx, id, f); err != nil {
			return err
		}
	}
	return nil
}

// void moves the object f guards off f.Version, unless it already moved
// or is gone.
func (s *Store) void(ctx context.Context, id string, f fence) error {
	for attempt := 0; ; attempt++ {
		u := &unstructured.Unstructured{}
		u.SetGroupVersionKind(GVK(f.Kind))
		err := translate(s.c.Get(ctx, client.ObjectKey{Namespace: s.ns, Name: f.Name}, u))
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if u.GetResourceVersion() != f.Version {
			return nil
		}
		ann := u.GetAnnotations()
		if ann == nil {
			ann = map[string]string{}
		}
		ann[voidAnno] = id
		u.SetAnnotations(ann)
		err = translate(s.c.Update(ctx, u))
		if errors.Is(err, store.ErrConflict) && attempt < 8 {
			continue
		}
		return err
	}
}
