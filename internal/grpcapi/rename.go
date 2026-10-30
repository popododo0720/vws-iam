package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"

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
//     pass until one pass finds nothing left.
//  5. commit: the old object is deleted at the version read. A group
//     moved by a concurrent user rename since the copy is copied again.
//  6. finish: RenamedFrom is cleared on the new object.
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
	// nothing else names the object.
	moveRefs func(ctx context.Context, from, to string) error
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
		moveRefs: func(ctx context.Context, from, to string) error { return s.moveUserRefs(ctx, p, from, to) },
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
			err = r.moveRefs(ctx, old, newName)
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
		dst, err := r.copyOf(ctx, src)
		if err != nil {
			return zero, err
		}
		from, _ := r.mutable(&src.Object)
		if r.moveRefs != nil {
			if err := r.moveRefs(ctx, *from, dst.Object.Key()); err != nil {
				return zero, err
			}
		}
		err = r.p.b.Delete(ctx, src.Object.Kind(), src.Object.Key(), src.Version)
		if err == nil || errors.Is(err, store.ErrNotFound) {
			return r.finish(ctx, dst)
		}
		if !errors.Is(err, store.ErrConflict) || attempt >= maxRenamePasses {
			return zero, errors.Join(errRenameBusy, err)
		}
		// Only rename writes touch a frozen object: a user rename moved a
		// member of this group since the copy. Copy again.
		again, err := store.Get[T](ctx, r.p.b, src.Object.Key())
		if errors.Is(err, store.ErrNotFound) {
			return r.finish(ctx, dst)
		}
		if err != nil {
			return zero, err
		}
		if r.uid(again.Object) != r.uid(src.Object) || again.Object.Rename().RenameTo != src.Object.Rename().RenameTo {
			return zero, errRenameBusy
		}
		src = again
	}
}

// copyOf creates the new object of src's rename, or brings the one an
// earlier attempt created up to date with src. A new name held by another
// object undoes the mark and is EntityAlreadyExists.
func (r renamer[T]) copyOf(ctx context.Context, src store.Versioned[T]) (store.Versioned[T], error) {
	var zero store.Versioned[T]
	want := src.Object
	name, st := r.mutable(&want)
	from := *name
	*name, st.RenamedFrom, st.RenameTo = src.Object.Rename().RenameTo, from, ""
	ver, err := store.CreateMarked(ctx, r.p.b, want)
	if err == nil {
		return store.Versioned[T]{Object: want, Version: ver}, nil
	}
	if !errors.Is(err, store.ErrExists) {
		return zero, err
	}
	got, err := store.Get[T](ctx, r.p.b, *name)
	if errors.Is(err, store.ErrNotFound) {
		return zero, errRenameBusy // deleted in between: the next call creates it
	}
	if err != nil {
		return zero, err
	}
	if r.uid(got.Object) != r.uid(src.Object) || store.Fold(got.Object.Rename().RenamedFrom) != store.Fold(from) {
		if uerr := r.undo(ctx, src); uerr != nil {
			return zero, uerr
		}
		return zero, alreadyExists(r.what + " " + quote(*name) + " already exists")
	}
	ver, err = store.UpdateMarked(ctx, r.p.b, want, got.Version)
	if err != nil {
		return zero, err
	}
	return store.Versioned[T]{Object: want, Version: ver}, nil
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
// driven from it. If the old name was created again by someone else, the
// references are left alone: they may be the new object's.
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
		case errors.Is(err, store.ErrNotFound) && r.moveRefs != nil:
			// Stragglers: a reference written by a call that read the
			// old name before the mark.
			if err := r.moveRefs(ctx, from, dst.Object.Key()); err != nil {
				return zero, err
			}
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return zero, err
		}
		obj := dst.Object
		_, st := r.mutable(&obj)
		st.RenamedFrom, st.RenameStarted = "", time.Time{}
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
// returns once a pass found nothing to move.
func (s *Server) moveUserRefs(ctx context.Context, p project, from, to string) error {
	// A case-only rename folds from and to alike: rewrite only names
	// that are not already to, so a pass settles.
	is := func(n string) bool { return n != "" && n != to && store.Fold(n) == store.Fold(from) }
	for range maxRenamePasses {
		moved := 0
		count := func(err error) error {
			switch {
			case err == nil, errors.Is(err, store.ErrConflict):
				moved++
				return nil
			case errors.Is(err, store.ErrNotFound):
				return nil
			}
			return err
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
			if hit {
				if _, err := store.UpdateMarked(ctx, p.b, g.Object, g.Version); count(err) != nil {
					return err
				}
			}
		}
		keys, err := store.List[iam.AccessKey](ctx, p.b)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if !k.Object.Root && is(k.Object.UserName) {
				k.Object.UserName = to
				if _, err := store.Update(ctx, p.b, k.Object, k.Version); count(err) != nil {
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
				if _, err := store.Update(ctx, p.b, d.Object, d.Version); count(err) != nil {
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
				if _, err := store.Update(ctx, p.b, d.Object, d.Version); count(err) != nil {
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
				if _, err := store.Update(ctx, s.b, v.Object, v.Version); count(err) != nil {
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

// renameMarks is the part of a stored user or group the sweep reads.
type renameMarks struct {
	Name string `json:"name"`
	iam.RenameState
}

// ResumeRenames finishes every user and group rename that has been in
// flight for at least renameGrace, in every project, and returns how many
// it finished. cmd/vws-iam runs it every few minutes on each replica;
// races between replicas are harmless.
func (s *Server) ResumeRenames(ctx context.Context) (int, error) {
	n := 0
	var errs []error
	for _, kind := range []iam.Kind{iam.KindUser, iam.KindGroup} {
		es, err := s.b.List(ctx, kind)
		if err != nil {
			return n, err
		}
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
	}
	return n, errors.Join(errs...)
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
	return err
}
