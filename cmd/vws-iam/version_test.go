package main

import (
	"runtime/debug"
	"testing"
)

func TestBuildVersion(t *testing.T) {
	vcs := func(rev, mod string) *debug.BuildInfo {
		return &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: rev}, {Key: "vcs.modified", Value: mod}}}
	}
	for _, c := range []struct {
		name, linked string
		info         *debug.BuildInfo
		ok           bool
		want         string
	}{
		{"linker wins", "v0.5.0", vcs("2af84c1e0123456789", "false"), true, "v0.5.0"},
		{"module version", "", &debug.BuildInfo{Main: debug.Module{Version: "v0.4.1"}}, true, "v0.4.1"},
		{"vcs revision", "", vcs("2af84c1e0123456789", "false"), true, "2af84c1e0123"},
		{"dirty tree", "", vcs("2af84c1e0123456789", "true"), true, "2af84c1e0123-dirty"},
		{"devel without vcs", "", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, ""},
		{"no build info", "", nil, false, ""},
	} {
		if got := buildVersion(c.linked, c.info, c.ok); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
