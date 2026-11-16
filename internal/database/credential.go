package database

import (
	"fmt"

	"github.com/bravo68web/atrium/pkg/crypto"
)

func (db *DB) hashStoredCredentials() error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_flags WHERE name = 'credential_hash_v1'`).Scan(&n); err != nil {
		return fmt.Errorf("credential hash: %w", err)
	}
	if n > 0 {
		return db.backfillAccessIDs()
	}

	rows, err := db.Query(`SELECT token, COALESCE(jti, '') FROM access_tokens`)
	if err != nil {
		return fmt.Errorf("credential hash: %w", err)
	}
	type accessRow struct{ token, jti string }
	var access []accessRow
	for rows.Next() {
		var row accessRow
		if err := rows.Scan(&row.token, &row.jti); err != nil {
			_ = rows.Close()
			return fmt.Errorf("credential hash: %w", err)
		}
		access = append(access, row)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("credential hash: %w", err)
	}
	_ = rows.Close()

	repl := map[string]string{}
	for _, row := range access {
		repl[row.token] = crypto.StoredAccessKey(row.token, row.jti)
	}

	refreshRows, err := db.Query(`SELECT token, COALESCE(access_token, '') FROM refresh_tokens`)
	if err != nil {
		return fmt.Errorf("credential hash: %w", err)
	}
	type refreshRow struct{ token, access string }
	var refreshes []refreshRow
	for refreshRows.Next() {
		var row refreshRow
		if err := refreshRows.Scan(&row.token, &row.access); err != nil {
			_ = refreshRows.Close()
			return fmt.Errorf("credential hash: %w", err)
		}
		refreshes = append(refreshes, row)
	}
	if err := refreshRows.Err(); err != nil {
		_ = refreshRows.Close()
		return fmt.Errorf("credential hash: %w", err)
	}
	_ = refreshRows.Close()

	for _, row := range refreshes {
		nextToken := row.token
		if !crypto.IsCredentialHash(row.token) {
			nextToken = crypto.CredentialHash(row.token)
		}
		nextAccess := row.access
		if row.access != "" {
			if mapped, ok := repl[row.access]; ok {
				nextAccess = mapped
			} else {
				nextAccess = crypto.StoredAccessKey(row.access, "")
			}
		}
		if nextToken == row.token && nextAccess == row.access {
			continue
		}
		if _, err := db.Exec(`UPDATE refresh_tokens SET token = ?, access_token = ? WHERE token = ?`, nextToken, nextAccess, row.token); err != nil {
			return fmt.Errorf("credential hash: %w", err)
		}
	}

	for _, row := range access {
		next := repl[row.token]
		jti := row.jti
		if len(next) > 4 && next[:4] == "jti:" && jti == "" {
			jti = next[4:]
		}
		if next == row.token && jti == row.jti {
			continue
		}
		if _, err := db.Exec(`UPDATE access_tokens SET token = ?, jti = ? WHERE token = ?`, next, jti, row.token); err != nil {
			return fmt.Errorf("credential hash: %w", err)
		}
	}

	if _, err := db.Exec(`INSERT INTO schema_flags (name) VALUES ('credential_hash_v1')`); err != nil {
		return fmt.Errorf("credential hash: %w", err)
	}
	return db.backfillAccessIDs()
}

func (db *DB) backfillAccessIDs() error {
	rows, err := db.Query(`SELECT token FROM access_tokens WHERE id IS NULL OR id = ''`)
	if err != nil {
		return fmt.Errorf("access token ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return fmt.Errorf("access token ids: %w", err)
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("access token ids: %w", err)
	}
	for _, token := range tokens {
		if _, err := db.Exec(`UPDATE access_tokens SET id = ? WHERE token = ? AND (id IS NULL OR id = '')`, newID(), token); err != nil {
			return fmt.Errorf("access token ids: %w", err)
		}
	}
	return nil
}
