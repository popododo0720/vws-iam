// Package archtest enforces the AGENTS.md rules that the compiler does not.
// Modeled on vws-compute's internal/archtest.
package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const module = "github.com/popododo0720/vws-iam"

// testSupport lists non-test packages that exist only to serve tests. They
// are exempt from the production rules, and no other non-test package may
// import "testing".
var testSupport = []string{"internal/store/storetest"}

func isModule(imp string) bool { return imp == module || strings.HasPrefix(imp, module+"/") }

func under(dir string, roots ...string) bool {
	for _, r := range roots {
		if dir == r || strings.HasPrefix(dir, r+"/") {
			return true
		}
	}
	return false
}

func hasPrefix(prefixes ...string) func(string) bool {
	return func(s string) bool {
		for _, p := range prefixes {
			if s == p || strings.HasPrefix(s, p+"/") {
				return true
			}
		}
		return false
	}
}

func onlyModule(allowed ...string) func(string) bool {
	return func(imp string) bool {
		if !isModule(imp) {
			return false
		}
		for _, a := range allowed {
			if imp == module+"/"+a {
				return false
			}
		}
		return true
	}
}

var transport = hasPrefix("google.golang.org/grpc", "google.golang.org/protobuf", "google.golang.org/genproto",
	"github.com/popododo0720/vws-proto", "cloud.google.com/go/longrunning")

// packageRules forbid imports inside one package directory.
var packageRules = []struct {
	dir    string
	forbid func(imp string) bool
	why    string
}{
	{"internal/iam", func(imp string) bool { return isModule(imp) || transport(imp) }, "the domain types are pure"},
	{"internal/policy", func(imp string) bool { return isModule(imp) || transport(imp) }, "the policy engine is pure"},
	{"internal/password", isModule, "password hashing imports nothing from this module"},
	{"internal/secret", onlyModule("internal/iam"), "sealing sees only the domain types"},
	{"internal/store", onlyModule("internal/iam"), "the store contract sees only the domain types"},
	{"internal/accesskey", transport, "domain services import no transport"},
	{"internal/authz", transport, "domain services import no transport"},
	{"internal/mfa", transport, "domain services import no transport"},
	{"internal/totp", func(imp string) bool { return isModule(imp) || transport(imp) }, "TOTP is pure"},
	{"internal/grpcapi", hasPrefix(module+"/internal/store/kubestore", module+"/internal/store/memstore"),
		"the server uses the store.Backend contract, not a backend's internals"},
}

// ownerRules confine an import to the directories that own it.
var ownerRules = []struct {
	match  func(imp string) bool
	owners []string
	why    string
}{
	{hasPrefix("database/sql"), nil, "no SQL: state lives in custom resources"},
	{func(imp string) bool { return imp == "log" || hasPrefix("github.com/getsentry")(imp) }, nil, "logs are slog through vws-lib obs"},
	{hasPrefix("google.golang.org/protobuf", "google.golang.org/genproto", "github.com/popododo0720/vws-proto", "cloud.google.com/go/longrunning"),
		[]string{"internal/grpcapi"}, "wire types stay in grpcapi"},
	{hasPrefix("google.golang.org/grpc"), []string{"internal/grpcapi", "cmd/vws-iam"}, "gRPC stays at the edge"},
	{hasPrefix("k8s.io", "sigs.k8s.io"), []string{"internal/store/kubestore"}, "Kubernetes client types stay in the custom resource store"},
	{hasPrefix("github.com/popododo0720/vws-lib"), []string{"internal/grpcapi", "cmd/vws-iam"}, "observability is wired at the edge"},
	{func(imp string) bool { return imp == "testing" }, testSupport, "production code does not import testing"},
}

// selectorRules confine every reference to a method name, call or method
// value, to the directories allowed to use it.
var selectorRules = []struct {
	names  []string
	owners []string
	why    string
}{
	{[]string{"GetSigningCredential"}, []string{"internal/accesskey", "internal/grpcapi"}, "a plaintext secret is opened only for signature checks"},
}

// constrainedDirs are the directories a rule constrains by name. Renaming
// one would silently disable its rule, so each must exist.
func constrainedDirs() []string {
	dirs := append([]string{}, testSupport...)
	for _, r := range packageRules {
		dirs = append(dirs, r.dir)
	}
	return dirs
}

// archViolations applies every rule to the non-test files in pkgs, keyed by
// slash-separated directory relative to the module root.
func archViolations(pkgs map[string][]*ast.File) []string {
	var bad []string
	for dir, files := range pkgs {
		if under(dir, testSupport...) {
			continue
		}
		for _, f := range files {
			for _, spec := range f.Imports {
				imp, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					bad = append(bad, fmt.Sprintf("%s: bad import %s", dir, spec.Path.Value))
					continue
				}
				for _, r := range packageRules {
					if dir == r.dir && r.forbid(imp) {
						bad = append(bad, fmt.Sprintf("%s imports %s: %s", dir, imp, r.why))
					}
				}
				for _, r := range ownerRules {
					if r.match(imp) && !under(dir, r.owners...) {
						bad = append(bad, fmt.Sprintf("%s imports %s: %s", dir, imp, r.why))
					}
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				for _, r := range selectorRules {
					for _, name := range r.names {
						if sel.Sel.Name == name && !under(dir, r.owners...) {
							bad = append(bad, fmt.Sprintf("%s uses %s: %s", dir, name, r.why))
						}
					}
				}
				return true
			})
		}
	}
	sort.Strings(bad)
	return bad
}

func loadProduction(t *testing.T, root string) map[string][]*ast.File {
	t.Helper()
	fset := token.NewFileSet()
	pkgs := map[string][]*ast.File{}
	err := walkFiles(root, func(rel string, data []byte) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return
		}
		f, err := parser.ParseFile(fset, rel, data, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		pkgs[dir] = append(pkgs[dir], f)
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

func TestArchitectureRules(t *testing.T) {
	// Every rule must catch a deliberate violation in a probe tree.
	probe := t.TempDir()
	for rel, src := range map[string]string{
		"internal/iam/i.go":                 `package iam; import _ "` + module + `/internal/store"`,
		"internal/policy/p.go":              `package policy; import _ "google.golang.org/protobuf/proto"`,
		"internal/password/p.go":            `package password; import _ "` + module + `/internal/iam"`,
		"internal/secret/s.go":              `package secret; import _ "` + module + `/internal/store"`,
		"internal/store/s.go":               `package store; import _ "database/sql"`,
		"internal/authz/a.go":               `package authz; import _ "google.golang.org/grpc"`,
		"internal/mfa/m.go":                 `package mfa; import _ "google.golang.org/grpc"`,
		"internal/totp/t.go":                `package totp; import _ "` + module + `/internal/iam"`,
		"internal/grpcapi/g.go":             `package grpcapi; import _ "` + module + `/internal/store/kubestore"; func f(s S) { s.GetSigningCredential() }`,
		"internal/widget/k.go":              `package widget; import _ "k8s.io/apimachinery/pkg/types"`,
		"internal/widget/l.go":              `package widget; import "log"; var _ = log.Println`,
		"internal/widget/w.go":              `package widget; import "testing"; var _ testing.TB`,
		"internal/widget/c.go":              `package widget; func f(s S) { c := s.GetSigningCredential; _ = c }`,
		"internal/store/storetest/s.go":     `package storetest; import "testing"; var _ testing.TB`,
		"internal/store/kubestore/k.go":     `package kubestore; import _ "sigs.k8s.io/controller-runtime/pkg/client"`,
		"internal/store/memstore/m_test.go": `package memstore; import "log"`,
	} {
		writeFile(t, filepath.Join(probe, rel), src)
	}
	want := []string{
		"internal/authz imports google.golang.org/grpc: domain services import no transport",
		"internal/authz imports google.golang.org/grpc: gRPC stays at the edge",
		"internal/mfa imports google.golang.org/grpc: domain services import no transport",
		"internal/mfa imports google.golang.org/grpc: gRPC stays at the edge",
		"internal/totp imports " + module + "/internal/iam: TOTP is pure",
		"internal/grpcapi imports " + module + "/internal/store/kubestore: the server uses the store.Backend contract, not a backend's internals",
		"internal/iam imports " + module + "/internal/store: the domain types are pure",
		"internal/password imports " + module + "/internal/iam: password hashing imports nothing from this module",
		"internal/policy imports google.golang.org/protobuf/proto: the policy engine is pure",
		"internal/policy imports google.golang.org/protobuf/proto: wire types stay in grpcapi",
		"internal/secret imports " + module + "/internal/store: sealing sees only the domain types",
		"internal/store imports database/sql: no SQL: state lives in custom resources",
		"internal/widget imports k8s.io/apimachinery/pkg/types: Kubernetes client types stay in the custom resource store",
		"internal/widget imports log: logs are slog through vws-lib obs",
		"internal/widget imports testing: production code does not import testing",
		"internal/widget uses GetSigningCredential: a plaintext secret is opened only for signature checks",
	}
	sort.Strings(want)
	if got := archViolations(loadProduction(t, probe)); !reflect.DeepEqual(got, want) {
		t.Fatalf("probe violations:\n got %q\nwant %q", got, want)
	}

	root := repoRoot(t)
	for _, dir := range constrainedDirs() {
		if _, err := os.Stat(filepath.Join(root, dir)); err != nil {
			t.Errorf("rule directory %s: %v", dir, err)
		}
	}
	for _, v := range archViolations(loadProduction(t, root)) {
		t.Error(v)
	}
}
