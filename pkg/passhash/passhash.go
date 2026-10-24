// Package passhash hashes and verifies passwords.
//
// Operators choose an implementation in internal/hashalgo/algo.go.
// The helpers here cover bcrypt, argon2id, and a fallback that can
// verify an older hash while writing a new one.
package passhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// DefaultBcryptCost matches bcrypt.DefaultCost so existing hashes verify.
const DefaultBcryptCost = bcrypt.DefaultCost

// DefaultArgon2 is the argon2id parameter set written by `oauth-cli init --hash argon2id`.
// Memory is kibibytes. 64 * 1024 is 64 MiB.
var DefaultArgon2 = Argon2Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 4,
	SaltLen:     16,
	KeyLen:      32,
}

// maxArgon2MemoryKiB caps a stored hash at 1 GiB so a corrupt row cannot
// ask the process to allocate an unbounded amount of memory.
const maxArgon2MemoryKiB = 1 << 20

var errMismatch = errors.New("password mismatch")

// Hasher hashes a password and checks it later.
// Hash must return a self-contained encoding: salt, parameters, and digest.
// Verify returns nil on match. Any error is an authentication failure.
// Do not put "wrong password" or "malformed hash" into the error text.
type Hasher interface {
	// ID is a short stable name, logged at startup. Examples: "bcrypt", "argon2id".
	ID() string
	Hash(password string) (string, error)
	Verify(encoded, password string) error
}

// Rehasher reports whether a stored hash should be rewritten with Hash.
type Rehasher interface {
	NeedsRehash(encoded string) bool
}

// Argon2Params selects argon2id settings. Zero fields are filled from DefaultArgon2.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// Bcrypt returns a hasher that uses bcrypt at cost.
// A cost of 0 uses DefaultBcryptCost.
func Bcrypt(cost int) Hasher {
	if cost == 0 {
		cost = DefaultBcryptCost
	}
	return bcryptHasher{cost: cost}
}

type bcryptHasher struct {
	cost int
}

func (h bcryptHasher) ID() string { return "bcrypt" }

func (h bcryptHasher) Hash(password string) (string, error) {
	sum, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(sum), nil
}

func (h bcryptHasher) Verify(encoded, password string) error {
	if bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password)) != nil {
		return errMismatch
	}
	return nil
}

func (h bcryptHasher) NeedsRehash(encoded string) bool {
	cost, err := bcrypt.Cost([]byte(encoded))
	if err != nil {
		return false
	}
	return cost != h.cost
}

func (h bcryptHasher) recognizes(encoded string) bool {
	return strings.HasPrefix(encoded, "$2a$") ||
		strings.HasPrefix(encoded, "$2b$") ||
		strings.HasPrefix(encoded, "$2y$")
}

// Recognizes reports a bcrypt modular-crypt hash.
func (h bcryptHasher) Recognizes(encoded string) bool { return h.recognizes(encoded) }

// Argon2id returns a hasher that writes PHC argon2id strings.
func Argon2id(p Argon2Params) Hasher {
	filled := DefaultArgon2
	if p.Memory != 0 {
		filled.Memory = p.Memory
	}
	if p.Iterations != 0 {
		filled.Iterations = p.Iterations
	}
	if p.Parallelism != 0 {
		filled.Parallelism = p.Parallelism
	}
	if p.SaltLen != 0 {
		filled.SaltLen = p.SaltLen
	}
	if p.KeyLen != 0 {
		filled.KeyLen = p.KeyLen
	}
	return argon2Hasher{p: filled}
}

type argon2Hasher struct {
	p Argon2Params
}

func (h argon2Hasher) ID() string { return "argon2id" }

func (h argon2Hasher) Hash(password string) (string, error) {
	if err := validateArgon2(h.p); err != nil {
		return "", err
	}
	salt := make([]byte, h.p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("argon2 salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, h.p.Iterations, h.p.Memory, h.p.Parallelism, h.p.KeyLen)
	return formatArgon2id(h.p, salt, key), nil
}

func (h argon2Hasher) Verify(encoded, password string) error {
	parsed, err := parseArgon2id(encoded)
	if err != nil {
		return errMismatch
	}
	if err := validateStoredArgon2(parsed); err != nil {
		return errMismatch
	}
	sum := argon2.IDKey([]byte(password), parsed.salt, parsed.iterations, parsed.memory, parsed.parallelism, uint32(len(parsed.key)))
	if subtle.ConstantTimeCompare(sum, parsed.key) != 1 {
		return errMismatch
	}
	return nil
}

func (h argon2Hasher) NeedsRehash(encoded string) bool {
	parsed, err := parseArgon2id(encoded)
	if err != nil {
		return false
	}
	return parsed.memory != h.p.Memory ||
		parsed.iterations != h.p.Iterations ||
		parsed.parallelism != h.p.Parallelism ||
		uint32(len(parsed.salt)) != h.p.SaltLen ||
		uint32(len(parsed.key)) != h.p.KeyLen
}

func (h argon2Hasher) recognizes(encoded string) bool {
	return strings.HasPrefix(encoded, "$argon2id$")
}

// Recognizes reports a PHC argon2id hash.
func (h argon2Hasher) Recognizes(encoded string) bool { return h.recognizes(encoded) }

// Fallback hashes with primary and verifies with primary, then legacy.
// NeedsRehash is true when primary would not have written the stored hash,
// so a later login can replace a legacy encoding.
func Fallback(primary, legacy Hasher) Hasher {
	if primary == nil {
		panic("passhash: primary hasher is nil")
	}
	return fallbackHasher{primary: primary, legacy: legacy}
}

type fallbackHasher struct {
	primary Hasher
	legacy  Hasher
}

func (f fallbackHasher) ID() string { return f.primary.ID() }

func (f fallbackHasher) Hash(password string) (string, error) {
	return f.primary.Hash(password)
}

func (f fallbackHasher) Verify(encoded, password string) error {
	if f.primary.Verify(encoded, password) == nil {
		return nil
	}
	if f.legacy != nil && f.legacy.Verify(encoded, password) == nil {
		return nil
	}
	return errMismatch
}

// Recognizes reports a hash the primary or the legacy hasher accepts.
func (f fallbackHasher) Recognizes(encoded string) bool {
	return Accepts(f.primary, encoded) || Accepts(f.legacy, encoded)
}

func (f fallbackHasher) NeedsRehash(encoded string) bool {
	if re, ok := f.primary.(Rehasher); ok && re.NeedsRehash(encoded) {
		return true
	}
	if rec, ok := f.primary.(recognizer); ok && !rec.recognizes(encoded) {
		return true
	}
	return false
}

type recognizer interface {
	recognizes(encoded string) bool
}

// Recognizer is the method a hasher returned from internal/hashalgo/algo.go
// implements when its encoding is not bcrypt or argon2id. User import stores
// password_hash only when Accepts reports true.
type Recognizer interface {
	Recognizes(encoded string) bool
}

// Accepts reports whether hasher can verify encoded.
// Built-in bcrypt and argon2id hashers accept their own prefixes.
// A fallback hasher accepts either side. A custom hasher accepts an encoding
// only when it implements Recognizer.
func Accepts(h Hasher, encoded string) bool {
	encoded = strings.TrimSpace(encoded)
	if h == nil || encoded == "" {
		return false
	}
	if r, ok := h.(Recognizer); ok {
		return r.Recognizes(encoded)
	}
	if r, ok := h.(recognizer); ok {
		return r.recognizes(encoded)
	}
	return false
}

type argon2Encoded struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

func validateArgon2(p Argon2Params) error {
	if p.Iterations < 1 || p.Parallelism < 1 || p.KeyLen < 4 || p.SaltLen < 8 {
		return fmt.Errorf("invalid argon2 parameters")
	}
	if p.Memory < 2*uint32(p.Parallelism) || p.Memory > maxArgon2MemoryKiB {
		return fmt.Errorf("invalid argon2 parameters")
	}
	return nil
}

func validateStoredArgon2(p argon2Encoded) error {
	if p.iterations < 1 || p.parallelism < 1 || len(p.key) < 4 || len(p.salt) == 0 {
		return errMismatch
	}
	if p.memory < 2*uint32(p.parallelism) || p.memory > maxArgon2MemoryKiB {
		return errMismatch
	}
	return nil
}

func formatArgon2id(p Argon2Params, salt, key []byte) string {
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		p.Memory,
		p.Iterations,
		p.Parallelism,
		enc.EncodeToString(salt),
		enc.EncodeToString(key),
	)
}

func parseArgon2id(encoded string) (argon2Encoded, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return argon2Encoded{}, errMismatch
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || fmt.Sprintf("v=%d", version) != parts[2] {
		return argon2Encoded{}, errMismatch
	}
	if version != argon2.Version {
		return argon2Encoded{}, errMismatch
	}

	var memory, iterations, parallelism uint32
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return argon2Encoded{}, errMismatch
	}
	if fmt.Sprintf("m=%d,t=%d,p=%d", memory, iterations, parallelism) != parts[3] || parallelism > 255 {
		return argon2Encoded{}, errMismatch
	}

	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return argon2Encoded{}, errMismatch
	}
	key, err := enc.DecodeString(parts[5])
	if err != nil {
		return argon2Encoded{}, errMismatch
	}

	return argon2Encoded{
		memory:      memory,
		iterations:  iterations,
		parallelism: uint8(parallelism),
		salt:        salt,
		key:         key,
	}, nil
}
