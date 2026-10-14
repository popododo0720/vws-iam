package archtest

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func walkFiles(root string, visit func(rel string, data []byte)) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "third_party" {
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		visit(filepath.ToSlash(rel), data)
		return nil
	})
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
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

// Built from escapes so this file does not contain what it forbids.
var forbiddenText = []string{
	"\u2122",
	"\u00ae",
	"\u00a9",
	"all rights " + "reserved",
}

func noticeViolations(root string) ([]string, error) {
	var bad []string
	err := walkFiles(root, func(rel string, data []byte) {
		if rel == "LICENSE" {
			return
		}
		lower := bytes.ToLower(data)
		for _, s := range forbiddenText {
			if bytes.Contains(lower, []byte(s)) {
				bad = append(bad, fmt.Sprintf("%s: contains %+q", rel, s))
			}
		}
	})
	return bad, err
}

func TestNoTrademarkNotices(t *testing.T) {
	probe := t.TempDir()
	writeFile(t, filepath.Join(probe, "README.md"), "Example Corp. All Rights "+"Reserved.\n")
	writeFile(t, filepath.Join(probe, "LICENSE"), "Trademarks \u00a9\n")
	got, err := noticeViolations(probe)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.HasPrefix(got[0], "README.md:") {
		t.Fatalf("probe violations = %q, want exactly README.md", got)
	}
	got, err = noticeViolations(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range got {
		t.Errorf("trademark or rights notice: %s", v)
	}
}

// manifestViolations allows only deploy/crds and deploy/rbac, and RBAC
// only as a namespaced Role without wildcards.
func manifestViolations(root string) ([]string, error) {
	var bad []string
	dir := filepath.Join(root, "deploy")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}
	err := walkFiles(dir, func(rel string, data []byte) {
		sub := filepath.ToSlash(filepath.Dir(rel))
		if sub != "crds" && sub != "rbac" {
			bad = append(bad, "deploy/"+rel+": only deploy/crds and deploy/rbac are allowed")
			return
		}
		if sub != "rbac" {
			return
		}
		if strings.Contains(string(data), "ClusterRole") {
			bad = append(bad, "deploy/"+rel+": RBAC is namespaced, no ClusterRole")
		}
		for i, line := range strings.Split(string(data), "\n") {
			code, _, _ := strings.Cut(line, "#")
			if strings.Contains(code, `"*"`) || strings.Contains(code, "'*'") || strings.Contains(code, "- *") || strings.Contains(code, "[*]") {
				bad = append(bad, fmt.Sprintf("deploy/%s:%d: no wildcards", rel, i+1))
			}
		}
	})
	return bad, err
}

func TestOnlyRBACAndCRDManifests(t *testing.T) {
	probe := t.TempDir()
	writeFile(t, filepath.Join(probe, "deploy/crds/ok.yaml"), "kind: CustomResourceDefinition\n")
	writeFile(t, filepath.Join(probe, "deploy/chart/Chart.yaml"), "name: x\n")
	writeFile(t, filepath.Join(probe, "deploy/rbac/role.yaml"), "kind: ClusterRole\nrules:\n- verbs: [\"*\"] # ok in a comment: \"*\"\n")
	got, err := manifestViolations(probe)
	if err != nil {
		t.Fatal(err)
	}
	want := "deploy/chart/Chart.yaml: only deploy/crds and deploy/rbac are allowed|deploy/rbac/role.yaml: RBAC is namespaced, no ClusterRole|deploy/rbac/role.yaml:3: no wildcards"
	if strings.Join(got, "|") != want {
		t.Fatalf("probe violations = %q", got)
	}
	got, err = manifestViolations(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range got {
		t.Error(v)
	}
}
