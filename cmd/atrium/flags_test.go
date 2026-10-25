package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/version"
)

func TestVersionFlagPrintsTheBuild(t *testing.T) {
	var buf bytes.Buffer
	_, err := parseArgs([]string{"--version"}, &buf)
	if !errors.Is(err, errVersion) {
		t.Fatalf("err %v", err)
	}
	got := strings.TrimSpace(buf.String())
	want := "atrium " + version.Line()
	if got != want {
		t.Fatalf("got %q", got)
	}
}

func TestHelpFlagListsTheFlags(t *testing.T) {
	var buf bytes.Buffer
	_, err := parseArgs([]string{"--help"}, &buf)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("err %v", err)
	}
	text := buf.String()
	for _, want := range []string{"Usage: atrium", "-config", "-port", "-db", "-version"} {
		if !strings.Contains(text, want) {
			t.Fatalf("help missing %s:\n%s", want, text)
		}
	}
}

func TestParseArgsReadsConfigPortAndDatabase(t *testing.T) {
	opt, err := parseArgs([]string{"--config", "cfg.yaml", "--port", "9090", "--db", "app.db"}, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if opt.configPath != "cfg.yaml" || opt.port != 9090 || opt.dbPath != "app.db" {
		t.Fatalf("opt %+v", opt)
	}
}
