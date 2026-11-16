package repository

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
	"github.com/google/uuid"
)

// AccessVerifier checks a JWT access token and returns its jti.
// Opaque bearers are not passed to it.
type AccessVerifier func(raw string) (string, error)

type TokenRepository struct {
	db     database.SQL
	verify AccessVerifier
}

func NewTokenRepository(db database.SQL) *TokenRepository {
	defer telemetry.Step("repository.NewTokenRepository")()
	return &TokenRepository{db: db}
}

// SetAccessVerifier enables JWT lookup. A signed token is rejected when this is unset.
func (r *TokenRepository) SetAccessVerifier(fn AccessVerifier) {
	if r == nil {
		return
	}
	r.verify = fn
}

func (r *TokenRepository) presentedAccessKey(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("token")
	}
	if strings.Count(raw, ".") == 2 {
		if r == nil || r.verify == nil {
			return "", fmt.Errorf("token")
		}
		jti, err := r.verify(raw)
		if err != nil || jti == "" {
			return "", fmt.Errorf("token")
		}
		return crypto.JTIKey(jti), nil
	}
	return crypto.CredentialHash(raw), nil
}

const accessColumns = `COALESCE(id, ''), token, client_id, user_id, scopes, token_type, dpop_jkt, COALESCE(cert_thumbprint, ''), expires_at, revoked,
		COALESCE(resource, ''), iat, COALESCE(jti, ''), COALESCE(org_id, ''), COALESCE(act, '')`

func (r *TokenRepository) SaveAccessToken(token *models.AccessToken) error {
	defer telemetry.Step("repository.TokenRepository.SaveAccessToken")()
	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now().UTC()
	}
	if token.ID == "" {
		token.ID = uuid.NewString()
	}
	if token.JTI == "" {
		token.JTI = compactJTI(token.Token)
	}
	stored := crypto.StoredAccessKey(token.Token, token.JTI)
	if strings.HasPrefix(stored, "jti:") {
		token.JTI = strings.TrimPrefix(stored, "jti:")
	}
	scopes, _ := json.Marshal(token.Scopes)
	query := `INSERT INTO access_tokens (id, token, client_id, user_id, scopes, token_type, dpop_jkt, cert_thumbprint, expires_at, revoked, resource, iat, jti, org_id, act)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		token.ID, stored, token.ClientID, token.UserID,
		string(scopes), token.TokenType, token.DPoPJKT, token.CertThumbprint,
		token.ExpiresAt, boolInt(token.Revoked),
		token.Resource, token.IssuedAt, token.JTI, token.OrgID, token.Act,
	)
	return err
}

func (r *TokenRepository) GetAccessToken(presented string) (*models.AccessToken, error) {
	defer telemetry.Step("repository.TokenRepository.GetAccessToken")()
	key, err := r.presentedAccessKey(presented)
	if err != nil {
		return nil, err
	}
	at, err := r.accessByKey(key)
	if err != nil {
		return nil, err
	}
	at.Token = presented
	return at, nil
}

func (r *TokenRepository) GetAccessTokenByKey(key string) (*models.AccessToken, error) {
	defer telemetry.Step("repository.TokenRepository.GetAccessTokenByKey")()
	at, err := r.accessByKey(key)
	if err != nil {
		return nil, err
	}
	at.Token = ""
	return at, nil
}

func (r *TokenRepository) accessByKey(key string) (*models.AccessToken, error) {
	at := &models.AccessToken{}
	var scopes string
	var revoked bit
	var issued dbTime
	err := r.db.QueryRow(`SELECT `+accessColumns+` FROM access_tokens WHERE token = ?`, key).Scan(
		&at.ID, &at.Token, &at.ClientID, &at.UserID,
		&scopes, &at.TokenType, &at.DPoPJKT, &at.CertThumbprint,
		&at.ExpiresAt, &revoked,
		&at.Resource, &issued, &at.JTI, &at.OrgID, &at.Act,
	)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(scopes), &at.Scopes); err != nil {
		return nil, err
	}
	at.Revoked = revoked.Bool()
	at.IssuedAt = issued.Time
	return at, nil
}

func (r *TokenRepository) RevokeAccessToken(presented string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeAccessToken")()
	key, err := r.presentedAccessKey(presented)
	if err != nil {
		return err
	}
	return r.RevokeStoredAccessToken(key)
}

func (r *TokenRepository) RevokeStoredAccessToken(key string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeStoredAccessToken")()
	if key == "" {
		return nil
	}
	_, err := r.db.Exec("UPDATE access_tokens SET revoked = 1 WHERE token = ?", key)
	return err
}

func (r *TokenRepository) RevokeAccessByID(id string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeAccessByID")()
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("token")
	}
	var found string
	if err := r.db.QueryRow(`SELECT id FROM access_tokens WHERE id = ?`, id).Scan(&found); err != nil {
		return err
	}
	_, err := r.db.Exec("UPDATE access_tokens SET revoked = 1 WHERE id = ?", id)
	return err
}

func (r *TokenRepository) SaveRefreshToken(token *models.RefreshToken) error {
	defer telemetry.Step("repository.TokenRepository.SaveRefreshToken")()
	if token.ID == "" {
		token.ID = uuid.NewString()
	}
	if token.FamilyID == "" {
		token.FamilyID = uuid.NewString()
	}
	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now().UTC()
	}
	scopes, _ := json.Marshal(token.Scopes)
	storedRefresh := token.Token
	if !crypto.IsCredentialHash(storedRefresh) {
		storedRefresh = crypto.CredentialHash(storedRefresh)
	}
	storedAccess := ""
	if token.AccessToken != "" {
		storedAccess = crypto.StoredAccessKey(token.AccessToken, "")
	}
	query := `INSERT INTO refresh_tokens (id, token, access_token, client_id, user_id, scopes, family_id, expires_at, revoked, resource, iat, jti, org_id, act)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		token.ID, storedRefresh, storedAccess, token.ClientID,
		token.UserID, string(scopes), token.FamilyID, token.ExpiresAt, boolInt(token.Revoked),
		token.Resource, token.IssuedAt, token.JTI, token.OrgID, token.Act,
	)
	return err
}

func scanRefresh(scan func(dest ...any) error) (*models.RefreshToken, error) {
	defer telemetry.Step("repository.scanRefresh")()
	rt := &models.RefreshToken{}
	var scopes string
	var id, family, userID sql.NullString
	var revoked bit
	var issued dbTime
	if err := scan(
		&id, &rt.Token, &rt.AccessToken, &rt.ClientID,
		&userID, &scopes, &family, &rt.ExpiresAt, &revoked,
		&rt.Resource, &issued, &rt.JTI, &rt.OrgID, &rt.Act,
	); err != nil {
		return nil, err
	}
	rt.ID = id.String
	rt.FamilyID = family.String
	rt.UserID = userID.String
	rt.Revoked = revoked.Bool()
	rt.IssuedAt = issued.Time
	if err := json.Unmarshal([]byte(scopes), &rt.Scopes); err != nil {
		return nil, err
	}
	return rt, nil
}

const refreshColumns = `COALESCE(id, ''), token, COALESCE(access_token, ''), client_id, user_id, scopes, COALESCE(family_id, ''), expires_at, revoked, COALESCE(resource, ''), iat, COALESCE(jti, ''), COALESCE(org_id, ''), COALESCE(act, '')`

func compactJTI(token string) string {
	defer telemetry.Step("repository.compactJTI")()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		JTI string `json:"jti"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	return claims.JTI
}

func (r *TokenRepository) GetRefreshToken(presented string) (*models.RefreshToken, error) {
	defer telemetry.Step("repository.TokenRepository.GetRefreshToken")()
	rt, err := scanRefresh(r.db.QueryRow(`SELECT `+refreshColumns+` FROM refresh_tokens WHERE token = ?`, crypto.CredentialHash(presented)).Scan)
	if err != nil {
		return nil, err
	}
	rt.Token = presented
	return rt, nil
}

func (r *TokenRepository) GetRefreshByID(id string) (*models.RefreshToken, error) {
	defer telemetry.Step("repository.TokenRepository.GetRefreshByID")()
	return scanRefresh(r.db.QueryRow(`SELECT `+refreshColumns+` FROM refresh_tokens WHERE id = ?`, id).Scan)
}

func (r *TokenRepository) RevokeRefreshToken(presented string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeRefreshToken")()
	_, err := r.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", crypto.CredentialHash(presented))
	return err
}

func (r *TokenRepository) RevokeRefreshByID(id string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeRefreshByID")()
	rt, err := r.GetRefreshByID(id)
	if err != nil {
		return err
	}
	if _, err := r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE id = ?`, id); err != nil {
		return err
	}
	return r.RevokeStoredAccessToken(rt.AccessToken)
}

func (r *TokenRepository) GetRefreshTokenByAccessToken(accessToken string) (*models.RefreshToken, error) {
	defer telemetry.Step("repository.TokenRepository.GetRefreshTokenByAccessToken")()
	key, err := r.presentedAccessKey(accessToken)
	if err != nil {
		return nil, err
	}
	return scanRefresh(r.db.QueryRow(`SELECT `+refreshColumns+` FROM refresh_tokens WHERE access_token = ?`, key).Scan)
}

func (r *TokenRepository) RevokeFamily(familyID string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeFamily")()
	if familyID == "" {
		return nil
	}
	rows, err := r.db.Query(`SELECT access_token FROM refresh_tokens WHERE family_id = ? AND access_token IS NOT NULL AND access_token != ''`, familyID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var access []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return err
		}
		access = append(access, token)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, token := range access {
		if _, err := r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE token = ?`, token); err != nil {
			return err
		}
	}
	_, err = r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?`, familyID)
	return err
}

func (r *TokenRepository) ListRefreshTokens(clientID, userID string) ([]*models.RefreshToken, error) {
	defer telemetry.Step("repository.TokenRepository.ListRefreshTokens")()
	query := `SELECT ` + refreshColumns + ` FROM refresh_tokens WHERE 1=1`
	args := []any{}
	if clientID != "" {
		query += ` AND client_id = ?`
		args = append(args, clientID)
	}
	if userID != "" {
		query += ` AND user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY expires_at DESC`
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]*models.RefreshToken, 0)
	for rows.Next() {
		rt, err := scanRefresh(rows.Scan)
		if err != nil {
			return nil, err
		}
		rt.Token = ""
		rt.AccessToken = ""
		out = append(out, rt)
	}
	return out, rows.Err()
}

func (r *TokenRepository) RevokeAllForUser(userID string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeAllForUser")()
	_, _ = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	_, err := r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	return err
}

func (r *TokenRepository) RevokeOtherFamilies(userID, keepAccessToken string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeOtherFamilies")()
	keepKey := ""
	keepFamily := ""
	if keepAccessToken != "" {
		if key, err := r.presentedAccessKey(keepAccessToken); err == nil {
			keepKey = key
		}
		if rt, err := r.GetRefreshTokenByAccessToken(keepAccessToken); err == nil {
			keepFamily = rt.FamilyID
		}
	}
	rows, err := r.db.Query(`SELECT COALESCE(family_id, ''), COALESCE(access_token, '') FROM refresh_tokens WHERE user_id = ? AND revoked = 0`, userID)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	type pair struct{ family, access string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.family, &p.access); err != nil {
			return err
		}
		pairs = append(pairs, p)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range pairs {
		if keepFamily != "" && p.family == keepFamily {
			continue
		}
		if p.access != "" && p.access != keepKey {
			_, _ = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE token = ?`, p.access)
		}
		if p.family != "" {
			_, _ = r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?`, p.family)
		}
	}
	if keepKey != "" {
		_, err = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE user_id = ? AND token != ?`, userID, keepKey)
	} else {
		_, err = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE user_id = ?`, userID)
	}
	return err
}

func (r *TokenRepository) RevokeAllForClient(clientID, userID string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeAllForClient")()
	_, _ = r.db.Exec("UPDATE access_tokens SET revoked = 1 WHERE client_id = ? AND user_id = ?", clientID, userID)
	_, _ = r.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE client_id = ? AND user_id = ?", clientID, userID)
	return nil
}

func (r *TokenRepository) ListAccessTokens(clientID, userID string) ([]*models.AccessToken, error) {
	defer telemetry.Step("repository.TokenRepository.ListAccessTokens")()
	query := `SELECT COALESCE(id, ''), client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked
		FROM access_tokens WHERE 1=1`
	args := []interface{}{}

	if clientID != "" {
		query += " AND client_id = ?"
		args = append(args, clientID)
	}
	if userID != "" {
		query += " AND user_id = ?"
		args = append(args, userID)
	}
	query += " ORDER BY expires_at DESC"

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	tokens := make([]*models.AccessToken, 0)
	for rows.Next() {
		at := &models.AccessToken{}
		var scopes string
		var revoked bit
		err := rows.Scan(
			&at.ID, &at.ClientID, &at.UserID,
			&scopes, &at.TokenType, &at.DPoPJKT,
			&at.ExpiresAt, &revoked,
		)
		if err != nil {
			return nil, err
		}
		at.Revoked = revoked.Bool()
		if err := json.Unmarshal([]byte(scopes), &at.Scopes); err != nil {
			return nil, err
		}
		tokens = append(tokens, at)
	}
	return tokens, nil
}
