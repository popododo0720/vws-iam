package iam

import "testing"

func TestRootLoginValidate(t *testing.T) {
	ok := RootLogin{Meta: Meta{UID: "r-1"}, PasswordHash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, r := range map[string]RootLogin{
		"no uid":    {PasswordHash: ok.PasswordHash},
		"plaintext": {Meta: ok.Meta, PasswordHash: "Root-Console-9"},
		"bcrypt":    {Meta: ok.Meta, PasswordHash: "$2a$10$abcdefghijklmnopqrstuv"},
		"empty":     {Meta: ok.Meta},
	} {
		if r.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if (Session{UserName: ""}).Root() != true || (Session{UserName: "alice"}).Root() {
		t.Fatal("Session.Root")
	}
}
