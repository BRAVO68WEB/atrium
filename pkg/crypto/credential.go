package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// CredentialHash is the hex SHA-256 of a presented bearer.
// The database stores this for an opaque token. It does not store the bearer.
func CredentialHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// IsCredentialHash reports a stored opaque-token key.
func IsCredentialHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// UnverifiedJTI reads jti from a JWT payload. It does not check the signature.
func UnverifiedJTI(raw string) (string, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.JTI == "" {
		return "", false
	}
	return claims.JTI, true
}

// JTIKey is the access_tokens primary key for a JWT. The signed token is not stored.
func JTIKey(jti string) string {
	return "jti:" + jti
}

// StoredAccessKey rewrites a legacy access bearer into its stored key.
// A value that is already a hash or a jti key is returned unchanged.
func StoredAccessKey(existing, jti string) string {
	if existing == "" || IsCredentialHash(existing) || strings.HasPrefix(existing, "jti:") {
		return existing
	}
	if parsed, ok := UnverifiedJTI(existing); ok {
		if jti == "" {
			jti = parsed
		}
		return JTIKey(jti)
	}
	if strings.Count(existing, ".") == 2 && jti != "" {
		return JTIKey(jti)
	}
	return CredentialHash(existing)
}

const secretPrefix = "enc:v1:"

// EncryptSecret seals a client secret with AES-256-GCM.
// An empty secret stays empty. A value that already has the prefix is unchanged.
func EncryptSecret(key []byte, plain string) (string, error) {
	if plain == "" || strings.HasPrefix(plain, secretPrefix) {
		return plain, nil
	}
	if len(key) != 32 {
		return "", fmt.Errorf("data key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return secretPrefix + base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptSecret opens a client secret. Plaintext is returned when the
// value has no prefix, so a row can be read before the startup rewrite.
func DecryptSecret(key []byte, stored string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, secretPrefix) {
		return stored, nil
	}
	if len(key) != 32 {
		return "", fmt.Errorf("data key must be 32 bytes")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(stored, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("client secret")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("client secret")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("client secret")
	}
	return string(plain), nil
}
