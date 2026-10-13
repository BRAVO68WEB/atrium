package hashalgo

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/bravo68web/oauth-impl/pkg/passhash"
	"golang.org/x/crypto/pbkdf2"
)

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// New passwords use PBKDF2-HMAC-SHA512 with 210000 iterations.
// A stored bcrypt hash does not verify.
// Verify compares the derived key with subtle.ConstantTimeCompare.
func Hash() passhash.Hasher {
	return pbkdf2Hasher{
		name:    "sha512",
		iter:    210000,
		saltLen: 16,
		keyLen:  32,
	}
}

type pbkdf2Hasher struct {
	name    string
	iter    int
	saltLen int
	keyLen  int
}

func (h pbkdf2Hasher) ID() string { return "pbkdf2-" + h.name }

func (h pbkdf2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2.Key([]byte(password), salt, h.iter, h.keyLen, sha512.New)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$pbkdf2-%s$i=%d$%s$%s", h.name, h.iter, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func (h pbkdf2Hasher) Verify(encoded, password string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "pbkdf2-"+h.name {
		return errPBKDF2
	}
	var iter int
	if _, err := fmt.Sscanf(parts[2], "i=%d", &iter); err != nil || fmt.Sprintf("i=%d", iter) != parts[2] || iter != h.iter {
		return errPBKDF2
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[3])
	if err != nil {
		return errPBKDF2
	}
	want, err := enc.DecodeString(parts[4])
	if err != nil || len(want) != h.keyLen {
		return errPBKDF2
	}
	key := pbkdf2.Key([]byte(password), salt, iter, len(want), sha512.New)
	if subtle.ConstantTimeCompare(key, want) != 1 {
		return errPBKDF2
	}
	return nil
}

var errPBKDF2 = mismatch("password mismatch")

type mismatch string

func (e mismatch) Error() string { return string(e) }
