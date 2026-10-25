package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/version"
)

func TestRootVersionFlag(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	want := "atrium-mobile " + version.Line()
	if got != want {
		t.Fatalf("got %q", got)
	}
}
