package repository

import (
	"encoding/json"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/google/uuid"
)

type AuditRow struct {
	ID         string         `json:"id"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type,omitempty"`
	TargetID   string         `json:"target_id,omitempty"`
	IP         string         `json:"ip,omitempty"`
	UserAgent  string         `json:"user_agent,omitempty"`
	Metadata   map[string]any `json:"metadata"`
	CreatedAt  string         `json:"created_at"`
}

type AuditRepository struct {
	db database.SQL
}

func NewAuditRepository(db database.SQL) *AuditRepository {
	defer telemetry.Step("repository.NewAuditRepository")()
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Insert(row AuditRow) error {
	defer telemetry.Step("repository.AuditRepository.Insert")()
	if r == nil || r.db == nil {
		return nil
	}
	if row.ID == "" {
		row.ID = uuid.NewString()
	}
	if row.CreatedAt == "" {
		row.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if row.Metadata == nil {
		row.Metadata = map[string]any{}
	}
	raw, err := json.Marshal(row.Metadata)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(`INSERT INTO audit_logs (id, actor_type, actor_id, action, target_type, target_id, ip, user_agent, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.ID, row.ActorType, row.ActorID, row.Action, row.TargetType, row.TargetID, row.IP, row.UserAgent, string(raw), row.CreatedAt)
	return err
}

func (r *AuditRepository) List(action, actorID string, since time.Time) ([]AuditRow, error) {
	defer telemetry.Step("repository.AuditRepository.List")()
	rows, err := r.db.Query(`SELECT id, actor_type, actor_id, action, COALESCE(target_type,''), COALESCE(target_id,''), COALESCE(ip,''), COALESCE(user_agent,''), metadata, created_at
		FROM audit_logs ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditRow
	for rows.Next() {
		var row AuditRow
		var raw string
		var created dbTime
		if err := rows.Scan(&row.ID, &row.ActorType, &row.ActorID, &row.Action, &row.TargetType, &row.TargetID, &row.IP, &row.UserAgent, &raw, &created); err != nil {
			return nil, err
		}
		row.CreatedAt = created.Time.UTC().Format(time.RFC3339)
		_ = json.Unmarshal([]byte(raw), &row.Metadata)
		if action != "" && row.Action != action {
			continue
		}
		if actorID != "" && row.ActorID != actorID {
			continue
		}
		if !since.IsZero() && created.Time.Before(since) {
			continue
		}
		out = append(out, row)
	}
	return out, rows.Err()
}
