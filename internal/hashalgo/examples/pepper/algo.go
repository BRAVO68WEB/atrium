package hashalgo

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/bravo68web/oauth-impl/pkg/passhash"
)

// pepper is a server secret. Changing it locks every password out.
// Keep it in this file. Do not move it to config.
const pepper = "replace-this-pepper"

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// The stored value is bcrypt of HMAC-SHA256(pepper, password).
func Hash() passhash.Hasher {
	return pepperHasher{next: passhash.Bcrypt(passhash.DefaultBcryptCost)}
}

type pepperHasher struct {
	next passhash.Hasher
}

func (h pepperHasher) ID() string { return "pepper" }

func (h pepperHasher) Hash(password string) (string, error) {
	return h.next.Hash(mix(password))
}

func (h pepperHasher) Verify(encoded, password string) error {
	return h.next.Verify(encoded, mix(password))
}

func mix(password string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(password))
	return string(mac.Sum(nil))
}
