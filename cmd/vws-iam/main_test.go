package main

import (
	"errors"
	"flag"
	"io"
	"testing"
)

func TestParseConfig(t *testing.T) {
	c, err := parseConfig([]string{"-namespace", "vws-iam", "-listen", ":1"}, io.Discard)
	if err != nil || c.namespace != "vws-iam" || c.listen != ":1" {
		t.Fatalf("%+v %v", c, err)
	}
	if _, err := parseConfig([]string{"extra"}, io.Discard); err == nil {
		t.Fatal("extra argument accepted")
	}
	if _, err := parseConfig([]string{"-h"}, io.Discard); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h: %v", err)
	}
}
