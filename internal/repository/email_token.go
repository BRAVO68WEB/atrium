package repository

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/google/uuid"
)

type EmailTokenRepository struct {
	db database.SQL
}

func NewEmailTokenRepository(db database.SQL) *EmailTokenRepository {
	defer telemetry.Step("repository.NewEmailTokenRepository")()
	return &EmailTokenRepository{db: db}
}

func (r *EmailTokenRepository) Create(userID, purpose string, ttl time.Duration) (string, error) {
	defer telemetry.Step("repository.EmailTokenRepository.Create")()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	now := time.Now()
	_, err := r.db.Exec(`INSERT INTO email_tokens (id, user_id, purpose, token_hash, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		uuid.NewString(), userID, purpose, hash, now.Add(ttl), now,
	)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (r *EmailTokenRepository) Consume(raw, purpose string) (string, error) {
	defer telemetry.Step("repository.EmailTokenRepository.Consume")()
	sum := sha256.Sum256([]byte(raw))
	hash := hex.EncodeToString(sum[:])
	var id, userID, stored string
	var expires time.Time
	err := r.db.QueryRow(`SELECT id, user_id, token_hash, expires_at FROM email_tokens
		WHERE token_hash = ? AND purpose = ? AND used_at IS NULL`, hash, purpose).Scan(&id, &userID, &stored, &expires)
	if err != nil {
		return "", err
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(hash)) != 1 {
		return "", sql.ErrNoRows
	}
	if time.Now().After(expires) {
		return "", sql.ErrNoRows
	}
	res, err := r.db.Exec(`UPDATE email_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL`, time.Now(), id)
	if err != nil {
		return "", err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return "", err
	}
	if n == 0 {
		return "", sql.ErrNoRows
	}
	return userID, nil
}
