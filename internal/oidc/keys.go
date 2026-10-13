package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/bravo68web/oauth-impl/internal/database"
	"time"
)

type storedKey struct {
	Kid      string
	Alg      string
	Status   string
	RSA      *rsa.PrivateKey
	EC       *ecdsa.PrivateKey
	RetireAt time.Time
}

func LoadKeySet(db database.SQL) (*KeySet, error) {
	ks := &KeySet{db: db}
	if db == nil {
		return newMemoryKeySet()
	}
	rows, err := db.Query(`SELECT kid, alg, status, private_pem, COALESCE(retire_at, '') FROM signing_keys`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kid, alg, status, pemText, retire string
		if err := rows.Scan(&kid, &alg, &status, &pemText, &retire); err != nil {
			return nil, err
		}
		key, err := parsePrivatePEM(alg, pemText)
		if err != nil {
			return nil, err
		}
		item := storedKey{Kid: kid, Alg: alg, Status: status, RSA: key.RSA, EC: key.EC}
		if retire != "" {
			item.RetireAt, _ = time.Parse(time.RFC3339, retire)
		}
		ks.keys = append(ks.keys, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if ks.active("RS256") == nil {
		if err := ks.generate("RS256"); err != nil {
			return nil, err
		}
	}
	if ks.active("ES256") == nil {
		if err := ks.generate("ES256"); err != nil {
			return nil, err
		}
	}
	return ks, nil
}

func newMemoryKeySet() (*KeySet, error) {
	ks := &KeySet{}
	if err := ks.generate("RS256"); err != nil {
		return nil, err
	}
	if err := ks.generate("ES256"); err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *KeySet) generate(alg string) error {
	item := storedKey{Alg: alg, Status: "active", Kid: generateKid()}
	var pemText string
	var err error
	switch alg {
	case "RS256":
		item.RSA, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		pemText = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(item.RSA)}))
	case "ES256":
		item.EC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		b, err := x509.MarshalECPrivateKey(item.EC)
		if err != nil {
			return err
		}
		pemText = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}))
	default:
		return fmt.Errorf("unknown alg %s", alg)
	}
	ks.mu.Lock()
	ks.keys = append(ks.keys, item)
	ks.mu.Unlock()
	if ks.db == nil {
		return nil
	}
	_, err = ks.db.Exec(`INSERT INTO signing_keys (kid, alg, status, private_pem, created_at) VALUES (?, ?, 'active', ?, ?)`,
		item.Kid, alg, pemText, time.Now().UTC().Format(time.RFC3339))
	return err
}

// Rotate retires the active key for each algorithm and creates a replacement.
func (ks *KeySet) Rotate(retain time.Duration) error {
	if retain <= 0 {
		retain = 48 * time.Hour
	}
	for _, alg := range []string{"RS256", "ES256"} {
		current := ks.active(alg)
		if err := ks.generate(alg); err != nil {
			return err
		}
		if current == nil {
			continue
		}
		retire := time.Now().Add(retain).UTC()
		ks.mu.Lock()
		for i := range ks.keys {
			if ks.keys[i].Kid == current.Kid {
				ks.keys[i].Status = "retired"
				ks.keys[i].RetireAt = retire
			}
		}
		ks.mu.Unlock()
		if ks.db != nil {
			_, err := ks.db.Exec(`UPDATE signing_keys SET status = 'retired', retire_at = ? WHERE kid = ?`, retire.Format(time.RFC3339), current.Kid)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (ks *KeySet) active(alg string) *storedKey {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for i := range ks.keys {
		if ks.keys[i].Alg == alg && ks.keys[i].Status == "active" {
			return &ks.keys[i]
		}
	}
	return nil
}

func (ks *KeySet) GetRSAKey() (*rsa.PrivateKey, string) {
	key := ks.active("RS256")
	if key == nil {
		return nil, ""
	}
	return key.RSA, key.Kid
}

func (ks *KeySet) GetECKey() (*ecdsa.PrivateKey, string) {
	key := ks.active("ES256")
	if key == nil {
		return nil, ""
	}
	return key.EC, key.Kid
}

func (ks *KeySet) publicByKid(kid string) (any, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for _, key := range ks.keys {
		if key.Kid != kid {
			continue
		}
		if key.RSA != nil {
			return &key.RSA.PublicKey, true
		}
		if key.EC != nil {
			return &key.EC.PublicKey, true
		}
	}
	return nil, false
}

func (ks *KeySet) ToJWKS() JWKS {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	now := time.Now()
	out := JWKS{}
	for _, key := range ks.keys {
		if key.Status != "active" && (key.RetireAt.IsZero() || !key.RetireAt.After(now)) {
			continue
		}
		if key.RSA == nil && key.EC == nil {
			continue
		}
		out.Keys = append(out.Keys, publicJWK(key))
	}
	return out
}

func publicJWK(key storedKey) JWK {
	if key.RSA != nil {
		return JWK{
			Kty: "RSA", Kid: key.Kid, Use: "sig", Alg: "RS256",
			N: base64.RawURLEncoding.EncodeToString(key.RSA.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(bigIntBytes(key.RSA.E)),
		}
	}
	ecdhKey, _ := key.EC.PublicKey.ECDH()
	raw := ecdhKey.Bytes()
	return JWK{
		Kty: "EC", Kid: key.Kid, Use: "sig", Alg: "ES256", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(raw[1:33]),
		Y: base64.RawURLEncoding.EncodeToString(raw[33:65]),
	}
}

func bigIntBytes(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var out []byte
	for v := e; v > 0; v >>= 8 {
		out = append([]byte{byte(v)}, out...)
	}
	return out
}

func parsePrivatePEM(alg, text string) (storedKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return storedKey{}, fmt.Errorf("invalid private key pem")
	}
	switch alg {
	case "RS256":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return storedKey{}, err
		}
		return storedKey{RSA: key}, nil
	case "ES256":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return storedKey{}, err
		}
		return storedKey{EC: key}, nil
	case "Ed25519":
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return storedKey{}, err
		}
		return storedKey{}, nil
	default:
		return storedKey{}, fmt.Errorf("unknown alg %s", alg)
	}
}
