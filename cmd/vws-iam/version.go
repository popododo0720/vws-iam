package main

import (
	"runtime/debug"

	"golang.org/x/mod/module"

	"github.com/popododo0720/vws-lib/obs"
)

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
	if v := info.Main.Version; v != "" && v != "(devel)" && !module.IsPseudoVersion(v) {
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
