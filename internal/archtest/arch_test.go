// Package archtest enforces the AGENTS.md rules that the compiler does not.
package archtest

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/popododo0720/vws-iam/"

type file struct {
	pkg     string // directory relative to the repo root
	path    string
	test    bool
	imports []string
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func goFiles(t *testing.T) []file {
	t.Helper()
	root := repoRoot(t)
	var out []file
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		if d.IsDir() && (rel == "third_party" || strings.HasPrefix(rel, ".")) && rel != "." {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		ff := file{pkg: filepath.ToSlash(filepath.Dir(rel)), path: rel, test: strings.HasSuffix(p, "_test.go")}
		for _, im := range f.Imports {
			s, err := strconv.Unquote(im.Path.Value)
			if err != nil {
				return err
			}
			ff.imports = append(ff.imports, s)
		}
		out = append(out, ff)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestArchitectureRules(t *testing.T) {
	for _, f := range goFiles(t) {
		for _, im := range f.imports {
			kube := strings.HasPrefix(im, "k8s.io/") || strings.HasPrefix(im, "sigs.k8s.io/")
			switch {
			case (f.pkg == "internal/iam" || f.pkg == "internal/policy") && !f.test && (strings.HasPrefix(im, module) || kube || strings.HasPrefix(im, "google.golang.org/")):
				t.Errorf("%s: internal/iam is pure but imports %s", f.path, im)
			case kube && !f.test && f.pkg != "internal/store/kubestore":
				t.Errorf("%s: Kubernetes import %s outside internal/store/kubestore", f.path, im)
			case im == "testing" && !f.test && f.pkg != "internal/store/storetest":
				t.Errorf("%s: production code imports testing", f.path)
			case im == "log" || strings.HasPrefix(im, "github.com/getsentry/"):
				t.Errorf("%s: use slog through vws-lib obs, not %s", f.path, im)
			case im == "database/sql":
				t.Errorf("%s: no SQL store", f.path)
			}
		}
	}
}

func TestOnlyRBACAndCRDManifests(t *testing.T) {
	root := repoRoot(t)
	err := filepath.WalkDir(filepath.Join(root, "deploy"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		if dir != "deploy/crds" && dir != "deploy/rbac" {
			t.Errorf("%s: only deploy/crds and deploy/rbac are allowed", rel)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s := string(b)
		if dir == "deploy/rbac" && (strings.Contains(s, "ClusterRole") || strings.Contains(s, "'*'") || strings.Contains(s, "[\"*\"]") || strings.Contains(s, "[*]")) {
			t.Errorf("%s: RBAC must be a namespaced Role without wildcards", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVendoredLib(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "replace github.com/popododo0720/vws-lib => ./third_party/vws-lib") {
		t.Fatal("vws-lib must come from third_party/vws-lib")
	}
}
