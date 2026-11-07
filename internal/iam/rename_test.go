package iam_test

import (
	"strings"
	"testing"
	"time"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// TestRenameStateValidation: stored rename markers are checked like names
// (#134), so a corrupt marker never drives a rename.
func TestRenameStateValidation(t *testing.T) {
	at := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	good := []iam.Object{
		iam.User{Name: "alice", RenameState: iam.RenameState{RenameTo: "bob", RenameStarted: at}},
		iam.User{Name: "bob", RenameState: iam.RenameState{RenamedFrom: "alice", RenameRequestID: "r-1", RenameStarted: at}},
		iam.User{Name: "bob", RenameState: iam.RenameState{RenameRequestID: "r-1"}},
		iam.User{Name: "bob", RenameState: iam.RenameState{RenamedFrom: "alice", RenameConfirmed: true, RenameStarted: at}},
		iam.Group{Name: "devs", RenameState: iam.RenameState{RenameTo: strings.Repeat("g", 128), RenameStarted: at}},
		iam.User{Name: "alice", RenameState: iam.RenameState{
			RenameTo: "bob", RenameStarted: at, RenameUndo: &iam.RenameUndo{Path: "/old/", Labels: map[string]string{"a": "b"}},
		}},
	}
	for _, o := range good {
		if err := o.Validate(); err != nil {
			t.Errorf("%+v: %v", o, err)
		}
	}
	bad := []iam.Object{
		iam.User{Name: "alice", RenameState: iam.RenameState{RenameTo: "bob", RenamedFrom: "carol", RenameStarted: at}},
		iam.User{Name: "alice", RenameState: iam.RenameState{RenameTo: "ALICE", RenameStarted: at}},
		iam.User{Name: "alice", RenameState: iam.RenameState{RenameTo: strings.Repeat("b", 65), RenameStarted: at}},
		iam.User{Name: "alice", RenameState: iam.RenameState{RenameTo: "b/c", RenameStarted: at}},
		iam.User{Name: "bob", RenameState: iam.RenameState{RenamedFrom: "bad name", RenameStarted: at}},
		iam.User{Name: "alice", RenameState: iam.RenameState{RenameTo: "bob"}},
		iam.User{Name: "alice", RenameState: iam.RenameState{RenameRequestID: "bad id!"}},
		iam.User{Name: "bob", RenameState: iam.RenameState{RenameConfirmed: true}},
		iam.User{Name: "alice", RenameState: iam.RenameState{RenameTo: "bob", RenameConfirmed: true, RenameStarted: at}},
		iam.Group{Name: "devs", RenameState: iam.RenameState{RenameTo: strings.Repeat("g", 129), RenameStarted: at}},
		iam.User{Name: "alice", RenameState: iam.RenameState{RenameUndo: &iam.RenameUndo{}}},
		iam.User{Name: "alice", RenameState: iam.RenameState{
			RenameTo: "bob", RenameStarted: at, RenameUndo: &iam.RenameUndo{Path: "no-slash"},
		}},
		iam.User{Name: "bob", RenameState: iam.RenameState{
			RenamedFrom: "alice", RenameStarted: at, RenameUndo: &iam.RenameUndo{},
		}},
	}
	for _, o := range bad {
		if err := o.Validate(); err == nil {
			t.Errorf("%+v validated", o)
		}
	}
	r := iam.RenameState{RenamedFrom: "alice"}
	if !r.Renaming() || r.RenamePartner() != "alice" {
		t.Errorf("%+v: renaming %v partner %q", r, r.Renaming(), r.RenamePartner())
	}
}

// TestIsRenamePartner: only the object with the same UID and the
// reciprocal marker is a rename partner (#180).
func TestIsRenamePartner(t *testing.T) {
	at := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	old := iam.User{
		Meta:        iam.Meta{UID: "u1"},
		Name:        "alice",
		RenameState: iam.RenameState{RenameTo: "bob", RenameStarted: at},
	}
	cp := iam.User{
		Meta:        iam.Meta{UID: "u1"},
		Name:        "Bob",
		RenameState: iam.RenameState{RenamedFrom: "ALICE", RenameStarted: at},
	}
	if !old.IsRenamePartner(cp) || !cp.IsRenamePartner(old) {
		t.Errorf("the two sides of one rename are not partners")
	}
	recreated := cp
	recreated.UID = "u2"
	unmarked := cp
	unmarked.RenameState = iam.RenameState{}
	other := iam.User{
		Meta:        iam.Meta{UID: "u1"},
		Name:        "carol",
		RenameState: iam.RenameState{RenamedFrom: "alice", RenameStarted: at},
	}
	for _, v := range []iam.User{recreated, unmarked, other, {}} {
		if old.IsRenamePartner(v) {
			t.Errorf("%+v is a partner of alice", v)
		}
	}
	if (iam.User{Meta: iam.Meta{UID: "u1"}, Name: "alice"}).IsRenamePartner(cp) {
		t.Errorf("an unmarked user has a partner")
	}
}
