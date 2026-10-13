package hashalgo

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/bravo68web/oauth-impl/pkg/passhash"
	"golang.org/x/crypto/scrypt"
)

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// scrypt is not in pkg/passhash. N=32768, r=8, p=1.
// Verify compares the derived key with subtle.ConstantTimeCompare.
func Hash() passhash.Hasher {
	return scryptHasher{n: 32768, r: 8, p: 1, saltLen: 16, keyLen: 32}
}

type scryptHasher struct {
	n, r, p, saltLen, keyLen int
}

func (h scryptHasher) ID() string { return "scrypt" }

func (h scryptHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(password), salt, h.n, h.r, h.p, h.keyLen)
	if err != nil {
		return "", err
	}
	return formatScrypt(h, salt, key), nil
}

func (h scryptHasher) Verify(encoded, password string) error {
	parsed, err := parseScrypt(encoded)
	if err != nil || parsed.n != h.n || parsed.r != h.r || parsed.p != h.p {
		return errScrypt
	}
	key, err := scrypt.Key([]byte(password), parsed.salt, parsed.n, parsed.r, parsed.p, len(parsed.key))
	if err != nil {
		return errScrypt
	}
	if subtle.ConstantTimeCompare(key, parsed.key) != 1 {
		return errScrypt
	}
	return nil
}

var errScrypt = mismatch("password mismatch")

type mismatch string

func (e mismatch) Error() string { return string(e) }

type scryptParsed struct {
	n, r, p int
	salt    []byte
	key     []byte
}

func formatScrypt(h scryptHasher, salt, key []byte) string {
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$scrypt$n=%d,r=%d,p=%d$%s$%s", h.n, h.r, h.p, enc.EncodeToString(salt), enc.EncodeToString(key))
}

func parseScrypt(encoded string) (scryptParsed, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "scrypt" {
		return scryptParsed{}, errScrypt
	}
	var n, r, p int
	if _, err := fmt.Sscanf(parts[2], "n=%d,r=%d,p=%d", &n, &r, &p); err != nil {
		return scryptParsed{}, errScrypt
	}
	if n < 2 || r < 1 || p < 1 || fmt.Sprintf("n=%d,r=%d,p=%d", n, r, p) != parts[2] {
		return scryptParsed{}, errScrypt
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[3])
	if err != nil {
		return scryptParsed{}, errScrypt
	}
	key, err := enc.DecodeString(parts[4])
	if err != nil {
		return scryptParsed{}, errScrypt
	}
	return scryptParsed{n: n, r: r, p: p, salt: salt, key: key}, nil
}
