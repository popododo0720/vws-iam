package archtest

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/modfile"
	gomodule "golang.org/x/mod/module"
	"golang.org/x/mod/semver"
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

// protoModulePath is the resource API module. It is consumed from a release tag through the module proxy.
const protoModulePath = "github.com/popododo0720/vws-proto"

// protoModuleRules returns the go.mod problems for the resource API module: a replace of it, a require
// that is not a release tag, or no require at all. Only the require and replace directives count, so an
// exclude or retract line naming a tag does not satisfy the rule.
func protoModuleRules(mod string) []string {
	f, err := modfile.Parse("go.mod", []byte(mod), nil)
	if err != nil {
		return []string{"go.mod does not parse: " + err.Error()}
	}
	var failures []string
	for _, r := range f.Replace {
		if r.Old.Path == protoModulePath {
			failures = append(failures, "go.mod replaces "+protoModulePath+" with "+r.New.String()+
				"; require a release tag instead")
		}
	}
	tagged := false
	for _, r := range f.Require {
		if r.Mod.Path != protoModulePath {
			continue
		}
		if !isReleaseTag(r.Mod.Version) {
			failures = append(failures, "go.mod requires "+r.Mod.String()+"; require a release tag vX.Y.Z instead")
			continue
		}
		tagged = true
	}
	if !tagged {
		failures = append(failures, "go.mod does not require "+protoModulePath+" at a release tag vX.Y.Z")
	}
	return failures
}

// isReleaseTag reports whether v is a release tag such as v0.5.0: canonical semver with no pre-release or
// build suffix, not a pseudo-version, and not the v0.0.0 placeholder.
func isReleaseTag(v string) bool {
	return semver.IsValid(v) && semver.Canonical(v) == v && semver.Prerelease(v) == "" &&
		!gomodule.IsPseudoVersion(v) && v != "v0.0.0"
}

// TestProtoModule: vws-proto comes from a release tag, with no replace, no copy and no generated code here.
func TestProtoModule(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	failures := protoModuleRules(string(b))
	if _, err := os.Stat(filepath.Join(root, "third_party", "vws-proto")); !os.IsNotExist(err) {
		failures = append(failures, "vendored copy third_party/vws-proto; require a vws-proto tag in go.mod instead")
	}
	err = walkFiles(root, func(rel string, _ []byte) {
		if strings.HasSuffix(rel, ".pb.go") {
			failures = append(failures, "generated protobuf "+rel+"; import it from the vws-proto module")
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) > 0 {
		t.Fatalf("vws-proto module rules:\n%s", strings.Join(failures, "\n"))
	}
}

func TestProtoModuleRules(t *testing.T) {
	const tagged = "require github.com/popododo0720/vws-proto v0.5.0\n"
	cases := []struct {
		name string
		mod  string
		bad  bool
	}{
		{"tag in a require block", "require (\n\tgithub.com/popododo0720/vws-proto v0.5.0\n)\n", false},
		{"single-line require", tagged, false},
		{"tag with indirect comment", "require (\n\tgithub.com/popododo0720/vws-proto v0.5.0 // indirect\n)\n", false},
		{"replace to a local copy", tagged + "replace github.com/popododo0720/vws-proto => ./third_party/vws-proto\n", true},
		{"replace in a block", tagged + "replace (\n\tgithub.com/popododo0720/vws-proto => ../vws-proto\n)\n", true},
		{"pseudo-version", "require github.com/popododo0720/vws-proto v0.4.1-0.20261021123535-8f0a84ed9918\n", true},
		{"placeholder version", "require github.com/popododo0720/vws-proto v0.0.0-00010101000000-000000000000\n", true},
		{"pre-release", "require github.com/popododo0720/vws-proto v0.6.0-rc.1\n", true},
		{"missing", "require google.golang.org/grpc v1.84.0\n", true},
		{
			"exclude block plus pseudo-version",
			"require github.com/popododo0720/vws-proto v0.4.1-0.20261021123535-8f0a84ed9918\n" +
				"exclude (\n\tgithub.com/popododo0720/vws-proto v0.5.0\n)\n", true,
		},
		{"v0.0.0 placeholder", "require github.com/popododo0720/vws-proto v0.0.0\n", true},
		{"not semver", "require github.com/popododo0720/vws-proto latest\n", true},
		{
			"replace of one version",
			tagged + "replace github.com/popododo0720/vws-proto v0.5.0 => example.com/fork v0.5.0\n", true,
		},
		{
			"valid tag in a full go.mod",
			"module example.com/x\n\ngo 1.26.0\n\nrequire (\n\tgithub.com/popododo0720/vws-proto v0.5.0\n" +
				"\tgoogle.golang.org/grpc v1.84.0\n)\n\nexclude github.com/popododo0720/vws-proto v0.4.0\n", false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := protoModuleRules(tc.mod)
			if (len(got) > 0) != tc.bad {
				t.Fatalf("protoModuleRules(%q) = %q, want failure %v", tc.mod, got, tc.bad)
			}
		})
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
