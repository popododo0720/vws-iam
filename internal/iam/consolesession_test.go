package iam

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConsoleSessionValidate(t *testing.T) {
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	ok := ConsoleSession{
		Hash: strings.Repeat("ab", 32), Project: "proj-a", ID: "web-1", UserName: "Alice", UserUID: "u-1",
		Created: now, Expires: now.Add(time.Hour), IdleTimeout: 15 * time.Minute,
	}
	root := ok
	root.UserName = ""
	for name, s := range map[string]ConsoleSession{"user": ok, "root": root} {
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, edit := range map[string]func(*ConsoleSession){
		"plaintext key":    func(s *ConsoleSession) { s.Hash = "my-session-token" },
		"upper-case hash":  func(s *ConsoleSession) { s.Hash = strings.Repeat("AB", 32) },
		"bad project":      func(s *ConsoleSession) { s.Project = "Proj_A" },
		"no id":            func(s *ConsoleSession) { s.ID = "" },
		"id with a slash":  func(s *ConsoleSession) { s.ID = "a/b" },
		"id of 64":         func(s *ConsoleSession) { s.ID = strings.Repeat("a", 64) },
		"bad user name":    func(s *ConsoleSession) { s.UserName = strings.Repeat("n", 65) },
		"no user uid":      func(s *ConsoleSession) { s.UserUID = "" },
		"no create time":   func(s *ConsoleSession) { s.Created = time.Time{} },
		"expires at birth": func(s *ConsoleSession) { s.Expires = s.Created },
		"negative idle":    func(s *ConsoleSession) { s.IdleTimeout = -time.Second },
	} {
		s := ok
		edit(&s)
		if err := s.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v, want ErrInvalid", name, err)
		}
	}
}
