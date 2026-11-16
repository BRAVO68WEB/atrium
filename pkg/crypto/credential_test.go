package crypto

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCredentialHashStable(t *testing.T) {
	got := CredentialHash("access-token-1")
	if !IsCredentialHash(got) {
		t.Fatalf("hash %q", got)
	}
	if got != CredentialHash("access-token-1") || got == CredentialHash("other") {
		t.Fatalf("hash %s", got)
	}
}

func TestStoredAccessKey(t *testing.T) {
	opaque := StoredAccessKey("access-token-1", "")
	if opaque != CredentialHash("access-token-1") {
		t.Fatalf("opaque %s", opaque)
	}
	if again := StoredAccessKey(opaque, ""); again != opaque {
		t.Fatalf("second pass %s", again)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"jti":"abc"}`))
	jwt := "aaa." + payload + ".sig"
	if got := StoredAccessKey(jwt, ""); got != "jti:abc" {
		t.Fatalf("jwt %s", got)
	}
	if got := StoredAccessKey("jti:abc", "abc"); got != "jti:abc" {
		t.Fatalf("already %s", got)
	}
}

func TestSecretRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := EncryptSecret(key, "client-secret")
	if err != nil || !strings.HasPrefix(sealed, "enc:v1:") {
		t.Fatalf("seal %q %v", sealed, err)
	}
	plain, err := DecryptSecret(key, sealed)
	if err != nil || plain != "client-secret" {
		t.Fatalf("open %q %v", plain, err)
	}
	again, err := EncryptSecret(key, sealed)
	if err != nil || again != sealed {
		t.Fatalf("second seal %q %v", again, err)
	}
	if got, err := DecryptSecret(nil, "still-plain"); err != nil || got != "still-plain" {
		t.Fatalf("plain %q %v", got, err)
	}
}
