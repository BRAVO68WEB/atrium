package testpg

import (
	"encoding/hex"
	"os"
	"testing"
)

func TestNewSessionIDIsUnique(t *testing.T) {
	first := newSessionID()
	second := newSessionID()
	if first == second {
		t.Fatalf("session ids match: %s", first)
	}
	if len(first) != 64 || len(second) != 64 {
		t.Fatalf("lengths %d %d", len(first), len(second))
	}
	if _, err := hex.DecodeString(first); err != nil {
		t.Fatal(err)
	}
}

func TestSessionIDIsSetForThisProcess(t *testing.T) {
	if os.Getenv("TESTCONTAINERS_SESSION_ID") == "" {
		t.Fatal("TESTCONTAINERS_SESSION_ID is empty")
	}
}
