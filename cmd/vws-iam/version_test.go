package main

import (
	"runtime/debug"
	"testing"
)

func TestBuildVersion(t *testing.T) {
	const rev = "c4ded37d70e1020b6358e6c596b935a4732ad822"
	info := func(modVersion, modified string) *debug.BuildInfo {
		return &debug.BuildInfo{
			Main: debug.Module{Version: modVersion},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: rev},
				{Key: "vcs.modified", Value: modified},
			},
		}
	}
	for _, c := range []struct {
		name, linked string
		info         *debug.BuildInfo
		ok           bool
		want         string
	}{
		{"linker wins", "v0.5.0", info("(devel)", "false"), true, "v0.5.0"},
		{"tagged module version wins", "", info("v0.4.1", "false"), true, "v0.4.1"},
		{"pre-release tag wins", "", info("v0.4.1-rc.1", "false"), true, "v0.4.1-rc.1"},
		{"pseudo-version falls through", "", info("v0.0.0-20261015160424-c4ded37d70e1", "false"), true, "c4ded37d70e1"},
		{
			"pseudo-version after a tag falls through", "",
			info("v0.4.2-0.20261015160424-c4ded37d70e1", "false"),
			true, "c4ded37d70e1",
		},
		{"dirty pseudo-version", "", info("v0.0.0-20261015160424-c4ded37d70e1+dirty", "true"), true, "c4ded37d70e1-dirty"},
		{
			"pseudo-version after a pre-release tag falls through", "",
			info("v0.4.1-rc.1.0.20261015160424-c4ded37d70e1", "false"),
			true, "c4ded37d70e1",
		},
		{
			"dirty pseudo-version after a pre-release tag", "",
			info("v0.4.1-rc.1.0.20261015160424-c4ded37d70e1+dirty", "true"),
			true, "c4ded37d70e1-dirty",
		},
		{"devel falls through", "", info("(devel)", "false"), true, "c4ded37d70e1"},
		{"empty module version falls through", "", info("", "false"), true, "c4ded37d70e1"},
		{"devel without vcs", "", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, ""},
		{"no build info", "", nil, false, ""},
	} {
		if got := buildVersion(c.linked, c.info, c.ok); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
