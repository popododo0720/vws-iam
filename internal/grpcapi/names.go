package grpcapi

import (
	"regexp"
	"strings"

	"github.com/popododo0720/vws-iam/internal/iam"
)

// parent parses projects/{project}.
func parent(s string) (string, error) {
	p, ok := strings.CutPrefix(s, "projects/")
	if !ok || !iam.ValidProject(p) {
		return "", invalidID("parent " + quote(s) + " is not projects/{project}")
	}
	return p, nil
}

// child parses projects/{project}/{collection}/{id}.
func child(s, collection string) (project, id string, err error) {
	parts := strings.Split(s, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[2] != collection || !iam.ValidProject(parts[1]) || parts[3] == "" {
		return "", "", invalidID("name " + quote(s) + " is not projects/{project}/" + collection + "/{id}")
	}
	return parts[1], parts[3], nil
}

// grandchild parses projects/{p}/{c1}/{id1}/{c2}/{id2}.
func grandchild(s, c1, c2 string) (project, id1, id2 string, err error) {
	parts := strings.Split(s, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != c1 || parts[4] != c2 || !iam.ValidProject(parts[1]) || parts[3] == "" || parts[5] == "" {
		return "", "", "", invalidID("name " + quote(s) + " is not projects/{project}/" + c1 + "/{id}/" + c2 + "/{id}")
	}
	return parts[1], parts[3], parts[5], nil
}

func quote(s string) string {
	if len(s) > 200 {
		s = s[:200]
	}
	return "\"" + s + "\""
}

func name(project, collection, id string) string {
	return "projects/" + project + "/" + collection + "/" + id
}

func checkID(id, what string) error {
	if !iam.ValidName(id) {
		return invalidID(what + " id " + quote(id) + " must match [A-Za-z0-9+=,.@_-]{1,64}")
	}
	return nil
}

var accessKeyID = regexp.MustCompile(`^AKIA[A-Z2-7]{16}$`)
