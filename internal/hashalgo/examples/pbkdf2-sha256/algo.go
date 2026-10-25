package hashalgo

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/bravo68web/atrium/pkg/passhash"
	"golang.org/x/crypto/pbkdf2"
)

// Hash is the only exported function in this file.
// Replace the body. Keep the name, the signature, and the package.
//
// New passwords use PBKDF2-HMAC-SHA256 with 600000 iterations.
// A stored bcrypt hash still verifies, and a successful login rewrites it.
// Verify compares the derived key with subtle.ConstantTimeCompare.
func Hash() passhash.Hasher {
	return passhash.Fallback(pbkdf2Hasher{
		name:    "sha256",
		iter:    600000,
		saltLen: 16,
		keyLen:  32,
	}, passhash.Bcrypt(passhash.DefaultBcryptCost))
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
	key := pbkdf2.Key([]byte(password), salt, h.iter, h.keyLen, sha256.New)
	return formatPBKDF2(h, salt, key), nil
}

func (h pbkdf2Hasher) Verify(encoded, password string) error {
	parsed, err := parsePBKDF2(h.name, encoded)
	if err != nil || parsed.iter != h.iter || len(parsed.key) != h.keyLen {
		return errPBKDF2
	}
	key := pbkdf2.Key([]byte(password), parsed.salt, parsed.iter, len(parsed.key), sha256.New)
	if subtle.ConstantTimeCompare(key, parsed.key) != 1 {
		return errPBKDF2
	}
	return nil
}

func (h pbkdf2Hasher) NeedsRehash(encoded string) bool {
	parsed, err := parsePBKDF2(h.name, encoded)
	if err != nil {
		return true
	}
	return parsed.iter != h.iter || len(parsed.key) != h.keyLen
}

var errPBKDF2 = mismatch("password mismatch")

type mismatch string

func (e mismatch) Error() string { return string(e) }

type pbkdf2Parsed struct {
	iter int
	salt []byte
	key  []byte
}

func formatPBKDF2(h pbkdf2Hasher, salt, key []byte) string {
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$pbkdf2-%s$i=%d$%s$%s", h.name, h.iter, enc.EncodeToString(salt), enc.EncodeToString(key))
}

func parsePBKDF2(name, encoded string) (pbkdf2Parsed, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "pbkdf2-"+name {
		return pbkdf2Parsed{}, errPBKDF2
	}
	var iter int
	if _, err := fmt.Sscanf(parts[2], "i=%d", &iter); err != nil || fmt.Sprintf("i=%d", iter) != parts[2] {
		return pbkdf2Parsed{}, errPBKDF2
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[3])
	if err != nil {
		return pbkdf2Parsed{}, errPBKDF2
	}
	key, err := enc.DecodeString(parts[4])
	if err != nil {
		return pbkdf2Parsed{}, errPBKDF2
	}
	return pbkdf2Parsed{iter: iter, salt: salt, key: key}, nil
}
