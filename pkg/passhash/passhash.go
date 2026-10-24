// Package passhash hashes and verifies passwords.
//
// Operators choose an implementation in internal/hashalgo/algo.go.
// The helpers here cover bcrypt, argon2id, PBKDF2, and salted digests
// (MD5, SHA-256, SHA-512, SHA3-512, and SHA-256 truncated to 16 bytes),
// plus a fallback that can verify an older hash while writing a new one.
package passhash

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
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
// Built-in hashers accept their own prefixes. A fallback hasher accepts
// either side. A custom hasher accepts an encoding only when it implements
// Recognizer.
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

// DefaultPBKDF2Iterations is the iteration count written by PBKDF2.
// OWASP recommends at least 600000 for PBKDF2-HMAC-SHA256.
const DefaultPBKDF2Iterations = 600_000

// maxPBKDF2Iterations caps a stored hash so one row cannot pin a CPU.
const maxPBKDF2Iterations = 10_000_000

// PBKDF2Params selects PBKDF2-HMAC-SHA256. Zero fields use the defaults.
type PBKDF2Params struct {
	Iterations int
	SaltLen    int
	KeyLen     int
}

// MD5 returns a salted MD5 hasher. The encoding is `$md5$<salt>$<digest>`.
// Use it to verify a migrated hash. New passwords should use bcrypt or
// argon2id, with MD5 as the legacy side of Fallback.
func MD5() Hasher { return newDigest("md5", "$md5$", 16, md5Sum) }

// SHA256 returns a salted SHA-256 hasher. The encoding is `$sha256$<salt>$<digest>`.
func SHA256() Hasher { return newDigest("sha256", "$sha256$", 32, sha256Sum) }

// SHA512 returns a salted SHA-512 hasher. The encoding is `$sha512$<salt>$<digest>`.
func SHA512() Hasher { return newDigest("sha512", "$sha512$", 64, sha512Sum) }

// SHA3512 returns a salted SHA3-512 hasher. The encoding is `$sha3-512$<salt>$<digest>`.
func SHA3512() Hasher { return newDigest("sha3-512", "$sha3-512$", 64, sha3512Sum) }

// SHA2_128 returns a salted hasher whose digest is the first 16 bytes of SHA-256.
// SHA-2 has no 128-bit hash. The encoding is `$sha2-128$<salt>$<digest>`.
func SHA2_128() Hasher { return newDigest("sha2-128", "$sha2-128$", 16, sha2128Sum) }

// PBKDF2 returns a PBKDF2-HMAC-SHA256 hasher.
// The encoding is `$pbkdf2-sha256$t=<iterations>$<salt>$<digest>`.
func PBKDF2(p PBKDF2Params) Hasher {
	if p.Iterations == 0 {
		p.Iterations = DefaultPBKDF2Iterations
	}
	if p.SaltLen == 0 {
		p.SaltLen = 16
	}
	if p.KeyLen == 0 {
		p.KeyLen = 32
	}
	return pbkdf2Hasher{p: p}
}

type digestFunc func(password, salt []byte) []byte

type digestHasher struct {
	id      string
	prefix  string
	size    int
	saltLen int
	sum     digestFunc
}

func newDigest(id, prefix string, size int, sum digestFunc) digestHasher {
	return digestHasher{id: id, prefix: prefix, size: size, saltLen: 16, sum: sum}
}

func (h digestHasher) ID() string { return h.id }

func (h digestHasher) Hash(password string) (string, error) {
	salt := make([]byte, h.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("%s salt: %w", h.id, err)
	}
	return formatDigest(h.prefix, salt, h.sum([]byte(password), salt)), nil
}

func (h digestHasher) Verify(encoded, password string) error {
	salt, key, err := parseDigest(h.prefix, encoded)
	if err != nil || len(key) != h.size {
		return errMismatch
	}
	sum := h.sum([]byte(password), salt)
	if subtle.ConstantTimeCompare(sum, key) != 1 {
		return errMismatch
	}
	return nil
}

func (h digestHasher) Recognizes(encoded string) bool {
	return strings.HasPrefix(encoded, h.prefix)
}

func (h digestHasher) recognizes(encoded string) bool { return h.Recognizes(encoded) }

func md5Sum(password, salt []byte) []byte {
	return saltedSum(md5.New(), password, salt)
}

func sha256Sum(password, salt []byte) []byte {
	return saltedSum(sha256.New(), password, salt)
}

func sha512Sum(password, salt []byte) []byte {
	return saltedSum(sha512.New(), password, salt)
}

func sha3512Sum(password, salt []byte) []byte {
	return saltedSum(sha3.New512(), password, salt)
}

func sha2128Sum(password, salt []byte) []byte {
	sum := saltedSum(sha256.New(), password, salt)
	return sum[:16]
}

func saltedSum(h hash.Hash, password, salt []byte) []byte {
	_, _ = h.Write(salt)
	_, _ = h.Write(password)
	return h.Sum(nil)
}

func formatDigest(prefix string, salt, key []byte) string {
	enc := base64.RawStdEncoding
	return prefix + enc.EncodeToString(salt) + "$" + enc.EncodeToString(key)
}

func parseDigest(prefix, encoded string) ([]byte, []byte, error) {
	if !strings.HasPrefix(encoded, prefix) {
		return nil, nil, errMismatch
	}
	rest := strings.TrimPrefix(encoded, prefix)
	saltText, keyText, ok := strings.Cut(rest, "$")
	if !ok || saltText == "" || keyText == "" || strings.Contains(keyText, "$") {
		return nil, nil, errMismatch
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(saltText)
	if err != nil {
		return nil, nil, errMismatch
	}
	key, err := enc.DecodeString(keyText)
	if err != nil {
		return nil, nil, errMismatch
	}
	return salt, key, nil
}

type pbkdf2Hasher struct {
	p PBKDF2Params
}

func (h pbkdf2Hasher) ID() string { return "pbkdf2-sha256" }

func (h pbkdf2Hasher) Hash(password string) (string, error) {
	if h.p.Iterations < 1 || h.p.SaltLen < 8 || h.p.KeyLen < 16 || h.p.Iterations > maxPBKDF2Iterations {
		return "", fmt.Errorf("invalid pbkdf2 parameters")
	}
	salt := make([]byte, h.p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("pbkdf2 salt: %w", err)
	}
	key := pbkdf2.Key([]byte(password), salt, h.p.Iterations, h.p.KeyLen, sha256.New)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$pbkdf2-sha256$t=%d$%s$%s", h.p.Iterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func (h pbkdf2Hasher) Verify(encoded, password string) error {
	parsed, err := parsePBKDF2(encoded)
	if err != nil {
		return errMismatch
	}
	sum := pbkdf2.Key([]byte(password), parsed.salt, parsed.iterations, len(parsed.key), sha256.New)
	if subtle.ConstantTimeCompare(sum, parsed.key) != 1 {
		return errMismatch
	}
	return nil
}

func (h pbkdf2Hasher) NeedsRehash(encoded string) bool {
	parsed, err := parsePBKDF2(encoded)
	if err != nil {
		return false
	}
	return parsed.iterations != h.p.Iterations || len(parsed.salt) != h.p.SaltLen || len(parsed.key) != h.p.KeyLen
}

func (h pbkdf2Hasher) Recognizes(encoded string) bool {
	return strings.HasPrefix(encoded, "$pbkdf2-sha256$")
}

func (h pbkdf2Hasher) recognizes(encoded string) bool { return h.Recognizes(encoded) }

type pbkdf2Encoded struct {
	iterations int
	salt       []byte
	key        []byte
}

func parsePBKDF2(encoded string) (pbkdf2Encoded, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "pbkdf2-sha256" {
		return pbkdf2Encoded{}, errMismatch
	}
	var iterations int
	if _, err := fmt.Sscanf(parts[2], "t=%d", &iterations); err != nil || fmt.Sprintf("t=%d", iterations) != parts[2] {
		return pbkdf2Encoded{}, errMismatch
	}
	if iterations < 1 || iterations > maxPBKDF2Iterations {
		return pbkdf2Encoded{}, errMismatch
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[3])
	if err != nil || len(salt) == 0 {
		return pbkdf2Encoded{}, errMismatch
	}
	key, err := enc.DecodeString(parts[4])
	if err != nil || len(key) < 16 {
		return pbkdf2Encoded{}, errMismatch
	}
	return pbkdf2Encoded{iterations: iterations, salt: salt, key: key}, nil
}
