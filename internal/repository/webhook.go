package repository

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type WebhookRepository struct {
	db database.SQL
}

func NewWebhookRepository(db database.SQL) *WebhookRepository {
	defer telemetry.Step("repository.NewWebhookRepository")()
	return &WebhookRepository{db: db}
}

func (r *WebhookRepository) Create(w *models.Webhook) error {
	defer telemetry.Step("repository.WebhookRepository.Create")()
	events, err := json.Marshal(w.Events)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(`INSERT INTO webhooks (id, url, secret, events, enabled, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		w.ID, w.URL, w.Secret, string(events), boolInt(w.Enabled), w.Description, w.CreatedAt, w.UpdatedAt,
	)
	return err
}

func (r *WebhookRepository) Update(w *models.Webhook) error {
	defer telemetry.Step("repository.WebhookRepository.Update")()
	events, err := json.Marshal(w.Events)
	if err != nil {
		return err
	}
	w.UpdatedAt = time.Now()
	res, err := r.db.Exec(`UPDATE webhooks SET url = ?, secret = ?, events = ?, enabled = ?, description = ?, updated_at = ? WHERE id = ?`,
		w.URL, w.Secret, string(events), boolInt(w.Enabled), w.Description, w.UpdatedAt, w.ID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("webhook not found")
	}
	return nil
}

func (r *WebhookRepository) Delete(id string) error {
	defer telemetry.Step("repository.WebhookRepository.Delete")()
	res, err := r.db.Exec(`DELETE FROM webhooks WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("webhook not found")
	}
	return nil
}

func (r *WebhookRepository) Get(id string) (*models.Webhook, error) {
	defer telemetry.Step("repository.WebhookRepository.Get")()
	return scanWebhook(r.db.QueryRow(`SELECT id, url, secret, events, enabled, COALESCE(description, ''), created_at, updated_at FROM webhooks WHERE id = ?`, id).Scan)
}

func (r *WebhookRepository) List() ([]*models.Webhook, error) {
	defer telemetry.Step("repository.WebhookRepository.List")()
	rows, err := r.db.Query(`SELECT id, url, secret, events, enabled, COALESCE(description, ''), created_at, updated_at FROM webhooks ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]*models.Webhook, 0)
	for rows.Next() {
		w, err := scanWebhook(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func scanWebhook(scan func(dest ...any) error) (*models.Webhook, error) {
	defer telemetry.Step("repository.scanWebhook")()
	w := &models.Webhook{}
	var events string
	var enabled int
	if err := scan(&w.ID, &w.URL, &w.Secret, &events, &enabled, &w.Description, &w.CreatedAt, &w.UpdatedAt); err != nil {
		return nil, err
	}
	w.Enabled = enabled != 0
	if events != "" && events != "null" {
		if err := json.Unmarshal([]byte(events), &w.Events); err != nil {
			return nil, err
		}
	}
	if w.Events == nil {
		w.Events = []string{}
	}
	return w, nil
}
