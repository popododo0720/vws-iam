package iam_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/popododo0720/vws-iam/internal/iam"
)

const slrUID = "ec720f7a-c0ba-4838-be33-f72e1873dd52"

func linkedRole(name, service string) iam.Role {
	return iam.Role{
		Meta: iam.Meta{UID: slrUID}, Name: name, Path: iam.ServiceRolePath(service),
		AssumeRolePolicy: `{"Version":"2012-10-17","Statement":[]}`, LinkedService: service,
	}
}

// TestDeletionTaskID: the AWS DeletionTaskId shape,
// task/aws-service-role/<service>/<role>/<uuid>, with the role's UID.
func TestDeletionTaskID(t *testing.T) {
	r := linkedRole("VWSServiceRoleForLexBots", "lex.vws.internal")
	want := "task/aws-service-role/lex.vws.internal/VWSServiceRoleForLexBots/" + slrUID
	if got := iam.DeletionTaskID(r); got != want {
		t.Fatalf("DeletionTaskID = %q, want %q", got, want)
	}
	service := strings.Repeat("s", 63) + "." + strings.Repeat("v", 63) + "." + strings.Repeat("w", 63) + ".internal"
	long := linkedRole(strings.Repeat("r", 64), service)
	if err := long.Validate(); err != nil {
		t.Fatal(err)
	}
	if n := len(iam.DeletionTaskID(long)); n > 1000 {
		t.Fatalf("DeletionTaskID of the longest names is %d characters, AWS allows 1000", n)
	}
}

// TestServiceLinkedRoleValidate: a service-linked role names a valid
// service principal, lives at /aws-service-role/<service>/ and has a UID;
// a role without LinkedService is never service-linked, whatever its path.
func TestServiceLinkedRoleValidate(t *testing.T) {
	ok := linkedRole("r", "ec2.vws.internal")
	if err := ok.Validate(); err != nil || !ok.ServiceLinked() {
		t.Fatalf("Validate = %v, ServiceLinked = %v", err, ok.ServiceLinked())
	}
	plain := ok
	plain.LinkedService = ""
	if err := plain.Validate(); err != nil || plain.ServiceLinked() {
		t.Fatalf("plain role at a service path: Validate = %v, ServiceLinked = %v", err, plain.ServiceLinked())
	}
	bad := map[string]func(*iam.Role){
		"no dot": func(r *iam.Role) { r.LinkedService, r.Path = "ec2", iam.ServiceRolePath("ec2") },
		"uppercase": func(r *iam.Role) {
			r.LinkedService, r.Path = "EC2.vws.internal", iam.ServiceRolePath("EC2.vws.internal")
		},
		"slash":         func(r *iam.Role) { r.LinkedService, r.Path = "a/b.vws", iam.ServiceRolePath("a/b.vws") },
		"too long":      func(r *iam.Role) { r.LinkedService = strings.Repeat("a.", 127) + "aa"; r.Path = "/" },
		"other path":    func(r *iam.Role) { r.Path = "/" },
		"other service": func(r *iam.Role) { r.Path = iam.ServiceRolePath("s3.vws.internal") },
		"path case":     func(r *iam.Role) { r.Path = "/AWS-service-role/ec2.vws.internal/" },
		"no uid":        func(r *iam.Role) { r.UID = "" },
		"bad uid":       func(r *iam.Role) { r.UID = "x" },
	}
	for name, mut := range bad {
		r := ok
		mut(&r)
		if err := r.Validate(); !errors.Is(err, iam.ErrInvalid) {
			t.Errorf("%s: Validate = %v, want ErrInvalid", name, err)
		}
	}
}
