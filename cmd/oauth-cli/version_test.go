package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bravo68web/oauth-impl/internal/version"
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
	want := "oauth-cli " + version.Line()
	if got != want {
		t.Fatalf("got %q", got)
	}
}
