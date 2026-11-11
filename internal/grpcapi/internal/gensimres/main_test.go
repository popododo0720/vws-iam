package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedSnapshot(t *testing.T) {
	want, err := os.ReadFile("../../simulation_resources_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := generate("../../testdata/simulation-resources")
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("pinned snapshot differs from simulation_resources_gen.go; run go generate ./internal/grpcapi")
		}
	}
}

func TestInvalidSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
		want string
	}{
		{"missing", "", "read iam snapshot"},
		{"malformed", "{", "decode iam snapshot"},
		{"no ARN", `{"Resources":[{"Name":"user","ARNFormats":[]}],"Actions":[]}`, "resource user has no ARN format"},
		{
			"unknown resource", `{"Resources":[],"Actions":[{"Name":"GetUser","Resources":[{"Name":"user"}]}]}`,
			"action GetUser references unknown resource user",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.data != "" {
				if err := os.WriteFile(filepath.Join(dir, "iam.json"), []byte(tc.data), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := generate(dir)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}
