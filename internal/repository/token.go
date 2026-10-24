package repository

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/google/uuid"
)

type TokenRepository struct {
	db database.SQL
}

func NewTokenRepository(db database.SQL) *TokenRepository {
	defer telemetry.Step("repository.NewTokenRepository")()
	return &TokenRepository{db: db}
}

func (r *TokenRepository) SaveAccessToken(token *models.AccessToken) error {
	defer telemetry.Step("repository.TokenRepository.SaveAccessToken")()
	if token.IssuedAt.IsZero() {
		token.IssuedAt = time.Now().UTC()
	}
	if token.JTI == "" {
		token.JTI = compactJTI(token.Token)
	}
	scopes, _ := json.Marshal(token.Scopes)
	query := `INSERT INTO access_tokens (token, client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked, resource, iat, jti, org_id, act)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		token.Token, token.ClientID, token.UserID,
		string(scopes), token.TokenType, token.DPoPJKT,
		token.ExpiresAt, boolInt(token.Revoked),
		token.Resource, token.IssuedAt, token.JTI, token.OrgID, token.Act,
	)
	return err
}

func (r *TokenRepository) GetAccessToken(token string) (*models.AccessToken, error) {
	defer telemetry.Step("repository.TokenRepository.GetAccessToken")()
	query := `SELECT token, client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked,
		COALESCE(resource, ''), iat, COALESCE(jti, ''), COALESCE(org_id, ''), COALESCE(act, '')
		FROM access_tokens WHERE token = ?`

	at := &models.AccessToken{}
	var scopes string
	var revoked bit
	var issued dbTime

	err := r.db.QueryRow(query, token).Scan(
		&at.Token, &at.ClientID, &at.UserID,
		&scopes, &at.TokenType, &at.DPoPJKT,
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

func (r *TokenRepository) RevokeAccessToken(token string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeAccessToken")()
	_, err := r.db.Exec("UPDATE access_tokens SET revoked = 1 WHERE token = ?", token)
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
	query := `INSERT INTO refresh_tokens (id, token, access_token, client_id, user_id, scopes, family_id, expires_at, revoked, resource, iat, jti, org_id, act)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		token.ID, token.Token, token.AccessToken, token.ClientID,
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

func (r *TokenRepository) GetRefreshToken(token string) (*models.RefreshToken, error) {
	defer telemetry.Step("repository.TokenRepository.GetRefreshToken")()
	return scanRefresh(r.db.QueryRow(`SELECT `+refreshColumns+` FROM refresh_tokens WHERE token = ?`, token).Scan)
}

func (r *TokenRepository) GetRefreshByID(id string) (*models.RefreshToken, error) {
	defer telemetry.Step("repository.TokenRepository.GetRefreshByID")()
	return scanRefresh(r.db.QueryRow(`SELECT `+refreshColumns+` FROM refresh_tokens WHERE id = ?`, id).Scan)
}

func (r *TokenRepository) RevokeRefreshToken(token string) error {
	defer telemetry.Step("repository.TokenRepository.RevokeRefreshToken")()
	_, err := r.db.Exec("UPDATE refresh_tokens SET revoked = 1 WHERE token = ?", token)
	return err
}

func (r *TokenRepository) GetRefreshTokenByAccessToken(accessToken string) (*models.RefreshToken, error) {
	defer telemetry.Step("repository.TokenRepository.GetRefreshTokenByAccessToken")()
	return scanRefresh(r.db.QueryRow(`SELECT `+refreshColumns+` FROM refresh_tokens WHERE access_token = ?`, accessToken).Scan)
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
	keepFamily := ""
	if keepAccessToken != "" {
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
		if p.access != "" && p.access != keepAccessToken {
			_, _ = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE token = ?`, p.access)
		}
		if p.family != "" {
			_, _ = r.db.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?`, p.family)
		}
	}
	if keepAccessToken != "" {
		_, err = r.db.Exec(`UPDATE access_tokens SET revoked = 1 WHERE user_id = ? AND token != ?`, userID, keepAccessToken)
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
	query := `SELECT token, client_id, user_id, scopes, token_type, dpop_jkt, expires_at, revoked
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
			&at.Token, &at.ClientID, &at.UserID,
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
