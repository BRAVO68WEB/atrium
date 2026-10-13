package aauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"
)

type signingKey struct {
	KID       string
	Private   ed25519.PrivateKey
	PublicB64 string
}

func loadOrCreateKey(db database.SQL) (signingKey, error) {
	if db == nil {
		return generateKey(nil)
	}
	var kid, pemText string
	err := db.QueryRow(`SELECT kid, private_pem FROM signing_keys WHERE alg = 'Ed25519' AND status = 'active' ORDER BY created_at LIMIT 1`).Scan(&kid, &pemText)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return signingKey{}, err
	}
	if err == nil {
		key, parseErr := parseEd25519(pemText)
		if parseErr != nil {
			return signingKey{}, parseErr
		}
		return signingKey{KID: kid, Private: key, PublicB64: publicB64(key)}, nil
	}
	return generateKey(db)
}

func generateKey(db database.SQL) (signingKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return signingKey{}, err
	}
	raw, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return signingKey{}, err
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return signingKey{}, err
	}
	kid := base64.RawURLEncoding.EncodeToString(buf)
	if db != nil {
		_, err = db.Exec(`INSERT INTO signing_keys (kid, alg, status, private_pem, created_at) VALUES (?, 'Ed25519', 'active', ?, ?)`,
			kid, pemText, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return signingKey{}, err
		}
	}
	return signingKey{KID: kid, Private: priv, PublicB64: base64.RawURLEncoding.EncodeToString(pub)}, nil
}

func parseEd25519(text string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, fmt.Errorf("invalid ed25519 private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key is not ed25519")
	}
	return key, nil
}

func publicB64(key ed25519.PrivateKey) string {
	pub := key.Public().(ed25519.PublicKey)
	return base64.RawURLEncoding.EncodeToString(pub)
}
