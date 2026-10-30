package iam

import (
	"strings"
	"time"
)

// RenameState records an in-flight rename of a user or group (AWS
// UpdateUser NewUserName, UpdateGroup NewGroupName, #134). A rename copies
// the object to its new key, so two objects take part:
//
//   - the old object carries RenameTo from the moment the rename is
//     accepted until it is deleted;
//   - the new object carries RenamedFrom from its creation until every
//     reference names it.
//
// While either is set the object is frozen: the store's typed writes
// refuse it with store.ErrRenaming, and only the rename coordinator writes
// it. The markers are the one place the rename's desired state lives, so a
// rename cut short by a crash is finished from them.
type RenameState struct {
	// RenameTo is the new name, on the old object.
	RenameTo string `json:"renameTo,omitempty"`
	// RenamedFrom is the old name, on the new object.
	RenamedFrom string `json:"renamedFrom,omitempty"`
	// RenameConfirmed is set on the new object, conditionally on the old
	// object still holding its mark at the version read, just before the
	// old object is deleted. A new object whose old object is gone is
	// promoted only when confirmed; an unconfirmed one was created by a
	// stale coordinator after the rename finished, and is dropped.
	RenameConfirmed bool `json:"renameConfirmed,omitempty"`
	// RenameRequestID is the request_id of the latest rename. It stays
	// after the rename finished, so a retry is answered from the new
	// object once the old one is gone.
	RenameRequestID string `json:"renameRequestId,omitempty"`
	// RenameStarted is when the in-flight rename was accepted.
	RenameStarted time.Time `json:"renameStarted,omitzero"`
}

// Renaming reports whether a rename of this object is in flight.
func (r RenameState) Renaming() bool { return r.RenameTo != "" || r.RenamedFrom != "" }

// RenamePartner is the other name of an in-flight rename, or "".
func (r RenameState) RenamePartner() string {
	if r.RenameTo != "" {
		return r.RenameTo
	}
	return r.RenamedFrom
}

// Rename returns the rename state; promoted to User and Group.
func (r RenameState) Rename() RenameState { return r }

func (r RenameState) check(what, name string, valid func(string) bool) error {
	switch {
	case r.RenameTo != "" && r.RenamedFrom != "":
		return invalid("%s %q is both a rename source and target", what, name)
	case r.RenameTo != "" && (!valid(r.RenameTo) || strings.EqualFold(r.RenameTo, name)):
		return invalid("%s %q rename target %q", what, name, r.RenameTo)
	case r.RenamedFrom != "" && (!valid(r.RenamedFrom) || strings.EqualFold(r.RenamedFrom, name)):
		return invalid("%s %q rename source %q", what, name, r.RenamedFrom)
	case r.RenameConfirmed && r.RenamedFrom == "":
		return invalid("%s %q rename confirmed without a source", what, name)
	case r.RenameRequestID != "" && !ValidRequestID(r.RenameRequestID):
		return invalid("%s %q rename request id", what, name)
	case r.Renaming() && r.RenameStarted.IsZero():
		return invalid("%s %q rename has no start time", what, name)
	}
	return nil
}

// Renamable is a stored object that can be renamed.
type Renamable interface {
	Object
	Rename() RenameState
}
