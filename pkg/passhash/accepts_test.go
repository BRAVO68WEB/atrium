package passhash

import (
	"strings"
	"testing"
)

type customHasher struct{}

func (customHasher) ID() string { return "custom" }

func (customHasher) Hash(password string) (string, error) {
	return "$custom$" + password, nil
}

func (customHasher) Verify(encoded, password string) error {
	if encoded == "$custom$"+password {
		return nil
	}
	return errMismatch
}

func (customHasher) Recognizes(encoded string) bool {
	return strings.HasPrefix(encoded, "$custom$")
}

func TestAcceptsCustomAndFallback(t *testing.T) {
	if !Accepts(customHasher{}, "$custom$secret") {
		t.Fatal("custom hash rejected")
	}
	if Accepts(customHasher{}, "$2a$junk") {
		t.Fatal("custom hasher accepted bcrypt")
	}
	both := Fallback(customHasher{}, Bcrypt(0))
	if !Accepts(both, "$custom$secret") || !Accepts(both, "$2a$10$abcdefghijklmnopqrstuu") {
		t.Fatal("fallback should accept either encoding")
	}
	if Accepts(both, "not-a-hash") {
		t.Fatal("unknown encoding accepted")
	}
}
