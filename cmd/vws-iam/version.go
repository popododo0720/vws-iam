package main

import (
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/popododo0720/vws-lib/obs"
)

// pseudoVersionRE matches a Go pseudo-version once +dirty or +incompatible is removed.
var pseudoVersionRE = regexp.MustCompile(`^v[0-9]+\.(0\.0-|\d+\.\d+-([0-9A-Za-z-]+\.)?0\.)\d{14}-[0-9a-f]+$`)

// version is set at link time: go build -ldflags "-X main.version=<tag or sha>".
// Without it the version comes from the build info (module version or VCS
// revision); with neither, vws-lib obs logs "devel".
var version string

// buildVersion picks the reported version: the linker value, then a
// tagged module version, then the 12-character VCS revision ("-dirty"
// when the tree was modified), else "" (obs reports "devel"). An untagged
// pseudo-version is not a release tag, so it falls through to the revision.
// A binary built from a checkout without -buildvcs data (for example a Docker
// context without .git) has no revision, so set -X there.
func buildVersion(linked string, info *debug.BuildInfo, ok bool) string {
	if linked != "" {
		return linked
	}
	if !ok || info == nil {
		return ""
	}
	if v := info.Main.Version; v != "" && v != "(devel)" && !untaggedPseudo(v) {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev != "" && dirty {
		rev += "-dirty"
	}
	return rev
}

func untaggedPseudo(v string) bool {
	base, _, _ := strings.Cut(v, "+")
	return strings.Count(base, "-") >= 2 && pseudoVersionRE.MatchString(base)
}

// withVersion passes the build's version to obs.Setup.
func withVersion() obs.Option {
	info, ok := debug.ReadBuildInfo()
	v := buildVersion(version, info, ok)
	return obs.WithOverride(func(c *obs.Config) {
		if c.Version == "" {
			c.Version = v
		}
	})
}
