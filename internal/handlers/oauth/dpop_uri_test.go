package oauth

import "testing"

func TestProofURIsUsesPublicIssuerWhenHostDiffers(t *testing.T) {
	got := proofURIs("http", "atrium:8080", "/oauth/token", "https://auth.example.com/")
	if len(got) != 2 {
		t.Fatalf("uris = %v", got)
	}
	if got[0] != "http://atrium:8080/oauth/token" {
		t.Fatalf("internal uri = %s", got[0])
	}
	if got[1] != "https://auth.example.com/oauth/token" {
		t.Fatalf("public uri = %s", got[1])
	}
}

func TestProofURIsSkipsDuplicateIssuer(t *testing.T) {
	got := proofURIs("https", "auth.example.com", "/oauth/token", "https://auth.example.com")
	if len(got) != 1 || got[0] != "https://auth.example.com/oauth/token" {
		t.Fatalf("uris = %v", got)
	}
}
