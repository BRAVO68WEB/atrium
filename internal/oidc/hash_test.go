package oidc

import "testing"

func TestTokenHashUsesTheLeftHalf(t *testing.T) {
	if got := TokenHash(""); got != "" {
		t.Fatalf("empty %q", got)
	}
	got := TokenHash("abc")
	if len(got) == 0 {
		t.Fatal("missing hash")
	}
	// SHA-256 left half is 16 bytes, which is 22 base64url characters without padding.
	if len(got) != 22 {
		t.Fatalf("len %d %q", len(got), got)
	}
}
