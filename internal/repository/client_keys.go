package repository

import (
	"database/sql"
	"time"

	"github.com/bravo68web/atrium/internal/telemetry"
)

type ClientSigningKey struct {
	ClientID   string
	Kid        string
	Alg        string
	Status     string
	PrivatePEM string
	PublicJWK  string
	CreatedAt  time.Time
	RetireAt   time.Time
}

func (r *ClientRepository) InsertClientSigningKey(key ClientSigningKey) error {
	defer telemetry.Step("repository.ClientRepository.InsertClientSigningKey")()
	sealed, err := r.Seal(key.PrivatePEM)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(`INSERT INTO client_signing_keys (client_id, kid, alg, status, private_pem, public_jwk, created_at)
		VALUES (?, ?, ?, 'active', ?, ?, ?)`,
		key.ClientID, key.Kid, key.Alg, sealed, key.PublicJWK, key.CreatedAt.UTC().Format(time.RFC3339))
	return err
}

func (r *ClientRepository) RetireClientSigningKey(kid string, retire time.Time) error {
	defer telemetry.Step("repository.ClientRepository.RetireClientSigningKey")()
	_, err := r.db.Exec(`UPDATE client_signing_keys SET status = 'retired', retire_at = ? WHERE kid = ?`,
		retire.UTC().Format(time.RFC3339), kid)
	return err
}

func (r *ClientRepository) ActiveClientSigningKey(clientID string) (kid, alg string, ok bool, err error) {
	defer telemetry.Step("repository.ClientRepository.ActiveClientSigningKey")()
	err = r.db.QueryRow(`SELECT kid, alg FROM client_signing_keys WHERE client_id = ? AND status = 'active'`, clientID).Scan(&kid, &alg)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return kid, alg, true, nil
}

func (r *ClientRepository) ListClientSigningKeys(clientID string) ([]ClientSigningKey, error) {
	defer telemetry.Step("repository.ClientRepository.ListClientSigningKeys")()
	rows, err := r.db.Query(`SELECT kid, alg, status, public_jwk, created_at, COALESCE(retire_at, '')
		FROM client_signing_keys WHERE client_id = ? ORDER BY created_at`, clientID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ClientSigningKey
	for rows.Next() {
		var key ClientSigningKey
		var created, retire string
		if err := rows.Scan(&key.Kid, &key.Alg, &key.Status, &key.PublicJWK, &created, &retire); err != nil {
			return nil, err
		}
		key.ClientID = clientID
		key.CreatedAt, _ = time.Parse(time.RFC3339, created)
		if retire != "" {
			key.RetireAt, _ = time.Parse(time.RFC3339, retire)
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

func (r *ClientRepository) PublishClientJWKS(clientID, jwks, jwksURI string) error {
	defer telemetry.Step("repository.ClientRepository.PublishClientJWKS")()
	_, err := r.db.Exec(`UPDATE clients SET jwks = ?, jwks_uri = ?, updated_at = ? WHERE id = ?`,
		jwks, jwksURI, time.Now().UTC(), clientID)
	return err
}

// PublishedClientSigningKeys returns public keys that are active or still inside the retain window.
func (r *ClientRepository) PublishedClientSigningKeys(now time.Time) ([]ClientSigningKey, error) {
	defer telemetry.Step("repository.ClientRepository.PublishedClientSigningKeys")()
	rows, err := r.db.Query(`SELECT client_id, kid, alg, status, public_jwk, created_at, COALESCE(retire_at, '')
		FROM client_signing_keys ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []ClientSigningKey
	for rows.Next() {
		var key ClientSigningKey
		var created, retire string
		if err := rows.Scan(&key.ClientID, &key.Kid, &key.Alg, &key.Status, &key.PublicJWK, &created, &retire); err != nil {
			return nil, err
		}
		key.CreatedAt, _ = time.Parse(time.RFC3339, created)
		if retire != "" {
			key.RetireAt, _ = time.Parse(time.RFC3339, retire)
		}
		if key.Status != "active" && (key.RetireAt.IsZero() || !key.RetireAt.After(now)) {
			continue
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

func (r *ClientRepository) DeleteClientSigningKeys(clientID string) error {
	defer telemetry.Step("repository.ClientRepository.DeleteClientSigningKeys")()
	_, err := r.db.Exec(`DELETE FROM client_signing_keys WHERE client_id = ?`, clientID)
	return err
}
