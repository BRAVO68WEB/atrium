package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	CodeVerifierMinLen = 43
	CodeVerifierMaxLen = 128
)

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateRandomString(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length], nil
}

func GenerateToken() (string, error) {
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func GenerateAuthorizationCode() (string, error) {
	return GenerateRandomString(32)
}

func GenerateUserCode() (string, error) {
	const charset = "BCDFGHJKLMNPQRSTVWXZ"
	bytes, err := GenerateRandomBytes(8)
	if err != nil {
		return "", err
	}

	code := make([]byte, 8)
	for i, b := range bytes {
		code[i] = charset[int(b)%len(charset)]
	}

	return fmt.Sprintf("%s-%s", string(code[:4]), string(code[4:])), nil
}

func GenerateDeviceCode() (string, error) {
	return GenerateRandomString(40)
}

func GenerateAuthReqID() (string, error) {
	return GenerateRandomString(32)
}

func GenerateRequestURI() (string, error) {
	id, err := GenerateRandomString(20)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", id), nil
}

func GenerateCodeVerifier() (string, error) {
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// SecretEqual compares two client secrets without leaking the match through a byte-by-byte scan.
func SecretEqual(got, want string) bool {
	sumGot := sha256.Sum256([]byte(got))
	sumWant := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(sumGot[:], sumWant[:]) == 1
}

func GenerateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func ValidateCodeChallenge(verifier, challenge, method string) bool {
	switch method {
	case "S256":
		computed := GenerateCodeChallenge(verifier)
		return computed == challenge
	case "plain":
		return verifier == challenge
	default:
		return false
	}
}

func ValidateCodeVerifier(verifier string) bool {
	if len(verifier) < CodeVerifierMinLen || len(verifier) > CodeVerifierMaxLen {
		return false
	}

	for _, c := range verifier {
		if !isUnreserved(c) {
			return false
		}
	}
	return true
}

func isUnreserved(c rune) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func Base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func Base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func NormalizeScopes(scopes string) []string {
	if scopes == "" {
		return nil
	}
	parts := strings.Fields(scopes)
	seen := make(map[string]bool)
	var result []string
	for _, s := range parts {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}

func JoinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}
