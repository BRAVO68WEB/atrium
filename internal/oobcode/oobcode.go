// Package oobcode implements the combined authorization code from
// draft-richer-oauth-oob-authcode-00.
//
// The draft names an HKDF info parameter and does not assign its bytes.
// This package uses the ASCII string in Info so the helper page and the
// client derive the same value.
package oobcode

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/url"
	"strings"

	"github.com/bravo68web/atrium/internal/telemetry"
	"golang.org/x/crypto/hkdf"
)

// Info is the HKDF info string shared by the helper page and the client.
const Info = "draft-richer-oauth-oob-authcode"

// Combine folds code and state into the single value the helper page shows.
func Combine(code, state string) (string, error) {
	defer telemetry.Step("oobcode.Combine")()
	if code == "" || state == "" {
		return "", fmt.Errorf("code and state are required")
	}
	c := []byte(code)
	ks, err := derivedKey(state, len(c))
	if err != nil {
		return "", err
	}
	encoded := make([]byte, len(c))
	for i := range c {
		encoded[i] = c[i] ^ ks[i]
	}
	sum := sha256.Sum256(c)
	return base64.RawURLEncoding.EncodeToString(sum[:3]) + base64.RawURLEncoding.EncodeToString(encoded), nil
}

// Recover extracts the authorization code from a combined value.
func Recover(combined, state string) (string, error) {
	defer telemetry.Step("oobcode.Recover")()
	combined = strings.TrimSpace(combined)
	if len(combined) <= 4 {
		return "", fmt.Errorf("combined code is too short")
	}
	checksum, err := base64.RawURLEncoding.DecodeString(combined[:4])
	if err != nil || len(checksum) != 3 {
		return "", fmt.Errorf("combined code checksum is invalid")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(combined[4:])
	if err != nil || len(encoded) == 0 {
		return "", fmt.Errorf("combined code is invalid")
	}
	ks, err := derivedKey(state, len(encoded))
	if err != nil {
		return "", err
	}
	raw := make([]byte, len(encoded))
	for i := range encoded {
		raw[i] = encoded[i] ^ ks[i]
	}
	sum := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(sum[:3], checksum) != 1 {
		return "", fmt.Errorf("combined code checksum mismatch")
	}
	return string(raw), nil
}

// FromPaste accepts a raw code, a combined code, or the helper page URL.
func FromPaste(pasted, state string, combined bool) (string, error) {
	defer telemetry.Step("oobcode.FromPaste")()
	pasted = strings.TrimSpace(pasted)
	if code, ok, err := codeFromURL(pasted, state); ok || err != nil {
		return code, err
	}
	if combined {
		return Recover(pasted, state)
	}
	if pasted == "" {
		return "", fmt.Errorf("authorization code is required")
	}
	return pasted, nil
}

func codeFromURL(pasted, state string) (string, bool, error) {
	defer telemetry.Step("oobcode.codeFromURL")()
	if !strings.Contains(pasted, "code=") {
		return "", false, nil
	}
	parsed, err := url.Parse(pasted)
	if err != nil {
		return "", false, nil
	}
	code := parsed.Query().Get("code")
	if code == "" {
		return "", false, nil
	}
	if got := parsed.Query().Get("state"); got != "" && got != state {
		return "", true, fmt.Errorf("state mismatch")
	}
	return code, true, nil
}

func derivedKey(state string, length int) ([]byte, error) {
	defer
	// A zero-length salt is what the draft specifies. A nil salt would
	// expand to a string of hash-length zeros instead.
	telemetry.Step("oobcode.derivedKey")()

	reader := hkdf.New(func() hash.Hash { return sha256.New() }, []byte(state), []byte{}, []byte(Info))
	key := make([]byte, length)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive code key: %w", err)
	}
	return key, nil
}
