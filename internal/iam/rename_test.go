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
