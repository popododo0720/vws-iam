package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/popododo0720/vws-iam/internal/iam"
	"github.com/popododo0720/vws-iam/internal/store"
)

// A rename (AWS UpdateUser NewUserName, UpdateGroup NewGroupName, #134)
// moves an object to a new key and keeps its UID, unique id, policies,
// keys, devices and memberships. Kubernetes has no multi-object
// transaction, so it runs as steps whose desired state lives in the
// objects' iam.RenameState markers, and every step can be repeated:
//
//  1. mark: the old object gets RenameTo under the caller's etag. From
//     here the rename only rolls forward, and both objects are frozen
//     (store.ErrRenaming) for every writer but this file.
//  2. fence (users): take and release the membership lock, so a member
//     add or key create that read the user before the mark cannot commit.
//  3. copy: the new object is created with RenamedFrom. A new name taken
//     by anything else undoes the mark and is EntityAlreadyExists.
//  4. references (users): group members, access keys, MFA devices, FIDO
//     keys and console sessions are moved to the new name, pass after
//     pass until one pass finds nothing left. Every move commits only
//     while the old object still holds the old name for this rename
//     (store.UpdateIf on it), so a reference of a user created again
//     under the old name is never moved.
//  5. commit: the copy is confirmed (RenameConfirmed) only while the old
//     object still holds the mark at the version read, then the old
//     object is deleted at that version. A copy whose old object is gone
//     is promoted only when confirmed, so a stale coordinator that copies
//     after the rename finished never brings a deleted object back. A group
//     moved by a concurrent user rename since the copy is copied again.
//     The copy of an existing new object commits only while the old
//     object is unchanged, so a coordinator holding a stale old object
//     never overwrites a fresher copy.
//  6. finish: RenamedFrom is cleared on the new object. Once the old
//     object is gone nothing names the old name: every writer that adds
//     a reference to a user is fenced against the mark (membership lock,
//     user version, or user UID), so no reference sweep runs then.
//
// A retry of the request, a rename to the same name, or the sweep
// (ResumeRenames, every few minutes on each replica) finishes a rename cut
// short by a crash.

// renameGrace is how old an in-flight rename must be before the sweep
// finishes it, so it does not race the request still running it.
// Correctness does not depend on it: every step is idempotent.
const renameGrace = time.Minute

// maxRenamePasses bounds the reference passes and commit attempts of one
// call. The rename stays marked and the sweep finishes it.
const maxRenamePasses = 8

// errRenameBusy is a rename that kept losing races. It stays marked.
var errRenameBusy = fmt.Errorf("%w: the rename did not settle; it is finished in the background", store.ErrConflict)

// errSourceMoved is a conditional rename write whose old object changed
// or is gone since it was read.
var errSourceMoved = fmt.Errorf("%w: the renamed object moved", store.ErrConflict)

func alreadyExists(msg string) error {
	return fail(codes.AlreadyExists, "ALREADY_EXISTS", "EntityAlreadyExists", msg)
}

// renamer adapts the rename steps to users or groups.
type renamer[T iam.Renamable] struct {
	s    *Server
	p    project
	what string
	// checkName validates the new name.
	checkName func(string) error
	// mutable returns the name and rename state of obj.
	mutable func(obj *T) (*string, *iam.RenameState)
	uid     func(T) string
	bump    func(*T)
	// moveRefs moves every reference from one name to another; nil when
	// nothing else names the object. A non-nil held returns, before each
	// move, the precondition that the old object still holds the name.
	moveRefs func(ctx context.Context, from, to string, held func(context.Context) (store.Pre, error)) error
}

func (s *Server) userRenamer(p project) renamer[iam.User] {
	return renamer[iam.User]{
		s: s, p: p, what: "user",
		checkName: func(n string) error { return checkID(n, "new user name") },
		mutable:   func(u *iam.User) (*string, *iam.RenameState) { return &u.Name, &u.RenameState },
		uid:       func(u iam.User) string { return u.UID },
		bump: func(u *iam.User) {
			u.Generation++
			u.Updated = s.now().UTC()
		},
		moveRefs: func(ctx context.Context, from, to string, held func(context.Context) (store.Pre, error)) error {
			return s.moveUserRefs(ctx, p, from, to, held)
		},
	}
}

func (s *Server) groupRenamer(p project) renamer[iam.Group] {
	return renamer[iam.Group]{
		s: s, p: p, what: "group",
		checkName: func(n string) error {
			if !iam.ValidGroupName(n) {
				return invalidID("new group name " + quote(n) + " must match " + iam.GroupNamePattern())
			}
			return nil
		},
		mutable: func(g *iam.Group) (*string, *iam.RenameState) { return &g.Name, &g.RenameState },
		uid:     func(g iam.Group) string { return g.UID },
		bump: func(g *iam.Group) {
			g.Generation++
			g.Updated = s.now().UTC()
		},
	}
}

// renameUser renames user old to newName; see renameEntity.
func (s *Server) renameUser(
	ctx context.Context, p project, old, newName, etag, requestID string,
	apply func(*iam.User) error, validateOnly bool,
) (store.Versioned[iam.User], error) {
	return renameEntity(ctx, s.userRenamer(p), old, newName, etag, requestID, apply, validateOnly)
}

// renameGroup renames group old to newName; see renameEntity.
func (s *Server) renameGroup(
	ctx context.Context, p project, old, newName, etag, requestID string,
	apply func(*iam.Group) error, validateOnly bool,
) (store.Versioned[iam.Group], error) {
	return renameEntity(ctx, s.groupRenamer(p), old, newName, etag, requestID, apply, validateOnly)
}

// renameEntity renames old to newName under etag (empty: any version) and
// returns the renamed object. apply changes the object in the same write
// as the mark (UpdateUser NewPath). A request_id that already renamed old
// to newName is answered from the new object, also after the old one is
// gone. A missing old object is NoSuchEntity; a new name taken by another
// object, case folded, is EntityAlreadyExists; a stale etag or a
// different rename in flight is ConcurrentModification.
func renameEntity[T iam.Renamable](
	ctx context.Context, r renamer[T], old, newName, etag, requestID string,
	apply func(*T) error, validateOnly bool,
) (store.Versioned[T], error) {
	var zero store.Versioned[T]
	if err := r.checkName(newName); err != nil {
		return zero, err
	}
	if requestID != "" && !iam.ValidRequestID(requestID) {
		return zero, invalidID("request_id must be 1 to 64 characters of [A-Za-z0-9_-]")
	}
	if requestID != "" && !validateOnly {
		done, err := store.Get[T](ctx, r.p.b, newName)
		switch {
		case err == nil && done.Object.Rename().RenameRequestID == requestID && done.Object.Rename().RenameTo == "":
			return r.finish(ctx, done)
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return zero, err
		}
	}
	for attempt := 0; ; attempt++ {
		cur, err := store.Get[T](ctx, r.p.b, old)
		if errors.Is(err, store.ErrNotFound) {
			return zero, notFound(r.what + " " + quote(old) + " does not exist")
		}
		if err != nil {
			return zero, err
		}
		name, st := r.mutable(&cur.Object)
		switch {
		case st.RenameTo != "" && store.Fold(st.RenameTo) == store.Fold(newName) &&
			((requestID != "" && st.RenameRequestID == requestID) || (requestID == "" && etag == "")):
			if validateOnly {
				return cur, nil
			}
			return r.drive(ctx, cur)
		case st.RenamedFrom != "" && attempt < maxRenamePasses:
			// old is the new side of an earlier rename: finish it first.
			if _, err := r.finish(ctx, cur); err != nil {
				return zero, err
			}
			continue
		case st.Renaming():
			return zero, fmt.Errorf("%s %q: %w", r.what, *name, store.ErrRenaming)
		}
		if err := checkEtag(etag, cur.Version); err != nil {
			return zero, err
		}
		if apply != nil {
			if err := apply(&cur.Object); err != nil {
				return zero, err
			}
		}
		sameKey := store.Fold(*name) == store.Fold(newName)
		if !sameKey {
			_, err := store.Get[T](ctx, r.p.b, newName)
			if err == nil {
				return zero, alreadyExists(r.what + " " + quote(newName) + " already exists")
			}
			if !errors.Is(err, store.ErrNotFound) {
				return zero, err
			}
		}
		if validateOnly {
			*name = newName
			return cur, cur.Object.Validate()
		}
		r.bump(&cur.Object)
		st.RenameRequestID = requestID
		if sameKey {
			// The same name or a change of case keeps the key: one
			// write, nothing frozen.
			*name = newName
			cur.Version, err = store.Update(ctx, r.p.b, cur.Object, cur.Version)
		} else {
			st.RenameTo, st.RenameStarted = newName, r.s.now().UTC()
			cur.Version, err = store.UpdateMarked(ctx, r.p.b, cur.Object, cur.Version)
		}
		if errors.Is(err, store.ErrConflict) && etag == "" && attempt < maxRenamePasses {
			continue
		}
		if errors.Is(err, store.ErrConflict) {
			return zero, checkEtag("stale", "")
		}
		if err == nil && sameKey && r.moveRefs != nil {
			// References compare case-insensitively; this only shows
			// the new case in group members.
			err = r.moveRefs(ctx, old, newName, nil)
		}
		if err != nil || sameKey {
			return cur, err
		}
		slog.Default().LogAttrs(ctx, slog.LevelInfo, "rename started", slog.String("project", r.p.id),
			slog.String("kind", r.what), slog.String("from", old), slog.String("to", newName))
		return r.drive(ctx, cur)
	}
}

// drive runs steps 2 to 6 for src, which carries RenameTo.
func (r renamer[T]) drive(ctx context.Context, src store.Versioned[T]) (store.Versioned[T], error) {
	var zero store.Versioned[T]
	if r.moveRefs != nil {
		_, unlock, err := r.p.lockMembership(ctx)
		if err != nil {
			return zero, err
		}
		unlock()
	}
	for attempt := 0; ; attempt++ {
		if attempt > maxRenamePasses {
			return zero, errRenameBusy
		}
		dst, created, err := r.copyOf(ctx, src)
		if err == nil && r.moveRefs != nil {
			from, _ := r.mutable(&src.Object)
			err = r.moveRefs(ctx, *from, dst.Object.Key(), func(ctx context.Context) (store.Pre, error) {
				cur, gone, err := r.reread(ctx, src)
				if err == nil && gone {
					err = errSourceMoved
				}
				return store.PreOf(cur), err
			})
		}
		if errors.Is(err, errSourceMoved) {
			again, gone, rerr := r.reread(ctx, src)
			switch {
			case rerr != nil:
				return zero, rerr
			case gone:
				return r.committed(ctx, dst, created)
			}
			src = again
			continue
		}
		if err != nil {
			return zero, err
		}
		// Conditional writes may move src's version (kubestore fences)
		// without changing it; anything else is copied again.
		again, gone, err := r.reread(ctx, src)
		if err != nil {
			return zero, err
		}
		if gone {
			return r.committed(ctx, dst, created)
		}
		if !sameSpec(again.Object, src.Object) {
			src = again
			continue
		}
		if !dst.Object.Rename().RenameConfirmed {
			dst, again, err = r.confirm(ctx, dst, again)
			switch {
			case errors.Is(err, errSourceMoved):
				src = again
				continue
			case errors.Is(err, errSourceGone):
				// Confirmed by the coordinator that committed: dst is
				// not this call's to drop.
				return r.committed(ctx, dst, false)
			case err != nil:
				return zero, err
			}
		}
		// The old object goes only while dst is still the copy confirm
		// wrote: a concurrent coordinator that rewrote dst since makes
		// the delete fail, and the copy is confirmed again first.
		err = r.p.b.DeleteIf(ctx, again.Object.Kind(), again.Object.Key(), again.Version, store.PreOf(dst))
		if err == nil {
			return r.finish(ctx, dst)
		}
		if errors.Is(err, store.ErrNotFound) {
			return r.committed(ctx, dst, created)
		}
		if !errors.Is(err, store.ErrConflict) {
			return zero, errors.Join(errRenameBusy, err)
		}
		// Only rename writes touch a frozen object: a user rename moved a
		// member of this group, or another coordinator rewrote dst, since
		// the copy. Copy again.
		src = again
	}
}

// errSourceGone is a confirm whose old object was deleted or replaced
// since it was read: another coordinator committed the rename.
var errSourceGone = errors.New("the renamed object is gone")

// confirm sets RenameConfirmed on dst, the copy of src's rename, only
// while src still holds the mark at the version read, and returns dst and
// src read again (a kubestore fence may move src's version). A refused
// write is errSourceMoved (src changed, or dst moved by a concurrent user
// rename) or errSourceGone. Only a confirmed copy is promoted once src is
// gone, so a copy a stale coordinator creates after the rename finished
// is dropped, not promoted (finish).
func (r renamer[T]) confirm(
	ctx context.Context, dst, src store.Versioned[T],
) (store.Versioned[T], store.Versioned[T], error) {
	obj := dst.Object
	_, st := r.mutable(&obj)
	st.RenameConfirmed = true
	ver, err := store.UpdateMarkedIf(ctx, r.p.b, obj, dst.Version, store.PreOf(src))
	if err != nil && !errors.Is(err, store.ErrConflict) {
		return dst, src, err
	}
	again, gone, rerr := r.reread(ctx, src)
	switch {
	case rerr != nil:
		return dst, src, rerr
	case gone && err == nil:
		// Confirmed while src held the mark; src went since.
		return store.Versioned[T]{Object: obj, Version: ver}, src, errSourceGone
	case gone:
		cur, gerr := store.Get[T](ctx, r.p.b, dst.Object.Key())
		if gerr != nil {
			return dst, src, gerr
		}
		return cur, src, errSourceGone
	case err != nil:
		return dst, again, errSourceMoved
	case !sameSpec(again.Object, src.Object):
		return store.Versioned[T]{Object: obj, Version: ver}, again, errSourceMoved
	}
	return store.Versioned[T]{Object: obj, Version: ver}, again, nil
}

// reread reads src again. gone reports that src's rename was committed
// by another coordinator: the old object is deleted, or its name holds
// another object. A mark undone since is errRenameBusy.
func (r renamer[T]) reread(ctx context.Context, src store.Versioned[T]) (store.Versioned[T], bool, error) {
	again, err := store.Get[T](ctx, r.p.b, src.Object.Key())
	switch {
	case errors.Is(err, store.ErrNotFound):
		return src, true, nil
	case err != nil:
		return src, false, err
	case r.uid(again.Object) != r.uid(src.Object):
		return src, true, nil
	case store.Fold(again.Object.Rename().RenameTo) != store.Fold(src.Object.Rename().RenameTo):
		return src, false, errRenameBusy
	}
	return again, false, nil
}

// committed handles a rename another coordinator committed while this
// one held a stale old object. If this call created dst and nobody wrote
// it since, dst was created after the committed copy was gone (deleted
// after the rename finished): it is removed again, not brought back.
func (r renamer[T]) committed(ctx context.Context, dst store.Versioned[T], created bool) (store.Versioned[T], error) {
	var zero store.Versioned[T]
	cur, err := store.Get[T](ctx, r.p.b, dst.Object.Key())
	if errors.Is(err, store.ErrNotFound) {
		return zero, notFound(r.what + " " + quote(dst.Object.Rename().RenamedFrom) + " does not exist")
	}
	if err != nil {
		return zero, err
	}
	if created && cur.Version == dst.Version {
		err := r.p.b.Delete(ctx, cur.Object.Kind(), cur.Object.Key(), cur.Version)
		if err == nil || errors.Is(err, store.ErrNotFound) {
			return zero, notFound(r.what + " " + quote(dst.Object.Rename().RenamedFrom) + " does not exist")
		}
		if !errors.Is(err, store.ErrConflict) {
			return zero, err
		}
		if cur, err = store.Get[T](ctx, r.p.b, dst.Object.Key()); err != nil {
			return zero, err
		}
	}
	if r.uid(cur.Object) != r.uid(dst.Object) {
		return zero, errRenameBusy
	}
	return r.finish(ctx, cur)
}

// sameSpec reports whether a and b store the same spec.
func sameSpec[T iam.Renamable](a, b T) bool {
	ja, erra := json.Marshal(a)
	jb, errb := json.Marshal(b)
	return erra == nil && errb == nil && bytes.Equal(ja, jb)
}

// copyOf creates the new object of src's rename, or brings the one an
// earlier attempt created up to date with src; created reports a create.
// The update commits only while src is unchanged (errSourceMoved). A new
// name held by another object undoes the mark and is EntityAlreadyExists.
func (r renamer[T]) copyOf(ctx context.Context, src store.Versioned[T]) (store.Versioned[T], bool, error) {
	var zero store.Versioned[T]
	want := src.Object
	name, st := r.mutable(&want)
	from := *name
	// The copy starts unconfirmed: until drive confirms it under the old
	// object's mark, finish never promotes it (RenameConfirmed).
	*name, st.RenamedFrom, st.RenameTo, st.RenameConfirmed = src.Object.Rename().RenameTo, from, "", false
	ver, err := store.CreateMarked(ctx, r.p.b, want)
	if err == nil {
		return store.Versioned[T]{Object: want, Version: ver}, true, nil
	}
	if !errors.Is(err, store.ErrExists) {
		return zero, false, err
	}
	got, err := store.Get[T](ctx, r.p.b, *name)
	if errors.Is(err, store.ErrNotFound) {
		return zero, false, errRenameBusy // deleted in between: the next call creates it
	}
	if err != nil {
		return zero, false, err
	}
	if r.uid(got.Object) != r.uid(src.Object) || store.Fold(got.Object.Rename().RenamedFrom) != store.Fold(from) {
		if _, gone, err := r.reread(ctx, src); err == nil && gone {
			// Committed by another coordinator, then the new object
			// was renamed or deleted: nothing to undo.
			return zero, false, notFound(r.what + " " + quote(from) + " does not exist")
		}
		if uerr := r.undo(ctx, src); uerr != nil {
			return zero, false, uerr
		}
		return zero, false, alreadyExists(r.what + " " + quote(*name) + " already exists")
	}
	// Never downgrade a copy confirmed under src's mark: the confirming
	// coordinator may delete src next, and an unconfirmed copy whose old
	// object is gone is dropped (finish).
	_, wst := r.mutable(&want)
	wst.RenameConfirmed = got.Object.Rename().RenameConfirmed
	ver, err = store.UpdateMarkedIf(ctx, r.p.b, want, got.Version, store.PreOf(src))
	if errors.Is(err, store.ErrConflict) {
		return got, false, errSourceMoved
	}
	if err != nil {
		return zero, false, err
	}
	return store.Versioned[T]{Object: want, Version: ver}, false, nil
}

// undo clears the mark of a rename whose new name was taken before the
// copy existed. It runs even when ctx ended, so the object is not left
// frozen.
func (r renamer[T]) undo(ctx context.Context, src store.Versioned[T]) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	obj := src.Object
	_, st := r.mutable(&obj)
	st.RenameTo, st.RenameRequestID, st.RenameStarted = "", "", time.Time{}
	if _, err := store.UpdateMarked(ctx, r.p.b, obj, src.Version); err != nil {
		return fmt.Errorf("undo rename of %s %q: %w", r.what, src.Object.Key(), err)
	}
	return nil
}

// finish runs step 6 on dst, the new object. If the old object is still
// there and still renamed to dst, the rename has not committed and is
// driven from it. Otherwise every reference was moved before the old
// object was deleted, and a reference to the old name now belongs to
// whoever holds that name again: it is left alone.
func (r renamer[T]) finish(ctx context.Context, dst store.Versioned[T]) (store.Versioned[T], error) {
	var zero store.Versioned[T]
	for attempt := 0; ; attempt++ {
		from := dst.Object.Rename().RenamedFrom
		if from == "" {
			return dst, nil
		}
		src, err := store.Get[T](ctx, r.p.b, from)
		switch {
		case err == nil && r.uid(src.Object) == r.uid(dst.Object) &&
			store.Fold(src.Object.Rename().RenameTo) == store.Fold(dst.Object.Key()):
			return r.drive(ctx, src)
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return zero, err
		}
		if !dst.Object.Rename().RenameConfirmed {
			// Never confirmed under the old object's mark: a stale
			// coordinator created dst after the rename finished (and the
			// new object was deleted or renamed again). Drop it.
			err := r.p.b.Delete(ctx, dst.Object.Kind(), dst.Object.Key(), dst.Version)
			if err == nil || errors.Is(err, store.ErrNotFound) {
				slog.Default().LogAttrs(ctx, slog.LevelInfo, "stale rename copy dropped", slog.String("project", r.p.id),
					slog.String("kind", r.what), slog.String("from", from), slog.String("to", dst.Object.Key()))
				return zero, notFound(r.what + " " + quote(from) + " does not exist")
			}
			if !errors.Is(err, store.ErrConflict) || attempt >= maxRenamePasses {
				return zero, err
			}
			if dst, err = store.Get[T](ctx, r.p.b, dst.Object.Key()); err != nil {
				return zero, err
			}
			continue
		}
		obj := dst.Object
		_, st := r.mutable(&obj)
		st.RenamedFrom, st.RenameStarted, st.RenameConfirmed = "", time.Time{}, false
		ver, err := store.UpdateMarked(ctx, r.p.b, obj, dst.Version)
		if err == nil {
			slog.Default().LogAttrs(ctx, slog.LevelInfo, "rename finished", slog.String("project", r.p.id),
				slog.String("kind", r.what), slog.String("from", from), slog.String("to", obj.Key()))
			return store.Versioned[T]{Object: obj, Version: ver}, nil
		}
		if !errors.Is(err, store.ErrConflict) || attempt >= maxRenamePasses {
			return zero, err
		}
		if dst, err = store.Get[T](ctx, r.p.b, dst.Object.Key()); err != nil {
			return zero, err
		}
	}
}

// moveUserRefs moves every reference to user from in project p to the
// name to: group members, access keys, MFA devices, FIDO keys and console
// sessions. A pass that moved something or lost a race is repeated, so it
// returns once a pass found nothing to move. With held, each move commits
// only while held's precondition (the old user) is unchanged.
func (s *Server) moveUserRefs(
	ctx context.Context, p project, from, to string, held func(context.Context) (store.Pre, error),
) error {
	// A case-only rename folds from and to alike: rewrite only names
	// that are not already to, so a pass settles.
	is := func(n string) bool { return n != "" && n != to && store.Fold(n) == store.Fold(from) }
	for range maxRenamePasses {
		moved := 0
		// move runs one reference write, under held's precondition.
		move := func(write func(pre *store.Pre) error) error {
			var pre *store.Pre
			if held != nil {
				v, err := held(ctx)
				if err != nil {
					return err
				}
				pre = &v
			}
			switch err := write(pre); {
			case err == nil, errors.Is(err, store.ErrConflict):
				moved++
				return nil
			case errors.Is(err, store.ErrNotFound):
				return nil
			default:
				return err
			}
		}
		groups, err := store.List[iam.Group](ctx, p.b)
		if err != nil {
			return err
		}
		for _, g := range groups {
			hit := false
			for i, m := range g.Object.Members {
				if is(m) {
					g.Object.Members[i], hit = to, true
				}
			}
			if !hit {
				continue
			}
			if err := move(func(pre *store.Pre) error {
				if pre == nil {
					_, err := store.UpdateMarked(ctx, p.b, g.Object, g.Version)
					return err
				}
				_, err := store.UpdateMarkedIf(ctx, p.b, g.Object, g.Version, *pre)
				return err
			}); err != nil {
				return err
			}
		}
		keys, err := store.List[iam.AccessKey](ctx, p.b)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if !k.Object.Root && is(k.Object.UserName) {
				k.Object.UserName = to
				if err := move(func(pre *store.Pre) error { return updateRef(ctx, p.b, k, pre) }); err != nil {
					return err
				}
			}
		}
		devs, err := store.List[iam.MfaDevice](ctx, p.b)
		if err != nil {
			return err
		}
		for _, d := range devs {
			if is(d.Object.UserName) {
				d.Object.UserName = to
				if err := move(func(pre *store.Pre) error { return updateRef(ctx, p.b, d, pre) }); err != nil {
					return err
				}
			}
		}
		fido, err := store.List[iam.FidoDevice](ctx, p.b)
		if err != nil {
			return err
		}
		for _, d := range fido {
			if is(d.Object.UserName) {
				d.Object.UserName = to
				if err := move(func(pre *store.Pre) error { return updateRef(ctx, p.b, d, pre) }); err != nil {
					return err
				}
			}
		}
		sessions, err := store.List[iam.Session](ctx, s.b)
		if err != nil {
			return err
		}
		for _, v := range sessions {
			if v.Object.Project == p.id && is(v.Object.UserName) {
				v.Object.UserName = to
				if err := move(func(pre *store.Pre) error {
					if pre != nil {
						// Sessions live outside the project scope.
						pre.Key = p.id + "/" + pre.Key
					}
					return updateRef(ctx, s.b, v, pre)
				}); err != nil {
					return err
				}
			}
		}
		if moved == 0 {
			return nil
		}
	}
	return errRenameBusy
}

// updateRef writes v back, conditionally on pre when it is set.
func updateRef[T iam.Object](ctx context.Context, b store.Backend, v store.Versioned[T], pre *store.Pre) error {
	var err error
	if pre == nil {
		_, err = store.Update(ctx, b, v.Object, v.Version)
	} else {
		_, err = store.UpdateIf(ctx, b, v.Object, v.Version, *pre)
	}
	return err
}

// renameMarks is the part of a stored user or group the sweep reads.
type renameMarks struct {
	Name string `json:"name"`
	iam.RenameState
}

// ResumeRenames finishes every user and group rename that has been in
// flight for at least renameGrace, in every project, and returns how many
// it finished. cmd/vws-iam runs it every few minutes on each replica;
// races between replicas are harmless. It lists in pages (gcPage).
func (s *Server) ResumeRenames(ctx context.Context) (int, error) {
	n := 0
	var errs []error
	for _, kind := range []iam.Kind{iam.KindUser, iam.KindGroup} {
		err := s.listPages(ctx, kind, func(es []store.Entry) {
			for _, e := range es {
				var m renameMarks
				if err := json.Unmarshal(e.Spec, &m); err != nil {
					errs = append(errs, fmt.Errorf("decode %s %s: %w", kind, e.Key, err))
					continue
				}
				pid, _, ok := strings.Cut(e.Key, "/")
				if !m.Renaming() || !ok || !iam.ValidProject(pid) || s.now().Sub(m.RenameStarted) < renameGrace {
					continue
				}
				p := s.project(pid)
				var err error
				if kind == iam.KindUser {
					err = resume(ctx, s.userRenamer(p), m.Name)
				} else {
					err = resume(ctx, s.groupRenamer(p), m.Name)
				}
				if err != nil {
					errs = append(errs, fmt.Errorf("%s %s: %w", kind, e.Key, err))
					continue
				}
				n++
			}
		})
		if err != nil {
			return n, err
		}
	}
	return n, errors.Join(errs...)
}

// listPages calls visit with every entry of kind, a page (gcPage) at a
// time when the backend pages (store.Pager), else all at once.
func (s *Server) listPages(ctx context.Context, kind iam.Kind, visit func([]store.Entry)) error {
	pager, ok := s.b.(store.Pager)
	if !ok {
		es, err := s.b.List(ctx, kind)
		if err != nil {
			return err
		}
		visit(es)
		return nil
	}
	for cont := ""; ; {
		es, next, err := pager.ListPage(ctx, kind, int64(s.gcPage), cont)
		if err != nil {
			return err
		}
		visit(es)
		if cont = next; cont == "" {
			return nil
		}
	}
}

// resume rolls the rename of name forward from whichever side it is.
func resume[T iam.Renamable](ctx context.Context, r renamer[T], name string) error {
	v, err := store.Get[T](ctx, r.p.b, name)
	if errors.Is(err, store.ErrNotFound) {
		return nil // finished by another replica
	}
	if err != nil {
		return err
	}
	switch st := v.Object.Rename(); {
	case st.RenameTo != "":
		_, err = r.drive(ctx, v)
	case st.RenamedFrom != "":
		_, err = r.finish(ctx, v)
	}
	if status.Code(err) == codes.NotFound {
		return nil // the object is gone: a stale copy was dropped
	}
	return err
}
