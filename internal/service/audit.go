package service

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
)

type AuditLog struct {
	repo *repository.AuditRepository
}

func NewAuditLog(repo *repository.AuditRepository) *AuditLog {
	defer telemetry.Step("service.NewAuditLog")()
	return &AuditLog{repo: repo}
}

func (a *AuditLog) Write(actorType, actorID, action, targetType, targetID string, r *http.Request, meta map[string]any) {
	defer telemetry.Step("service.AuditLog.Write")()
	if a == nil || a.repo == nil {
		return
	}
	row := repository.AuditRow{
		ActorType: actorType, ActorID: actorID, Action: action,
		TargetType: targetType, TargetID: targetID, Metadata: meta,
	}
	if r != nil {
		row.IP = r.RemoteAddr
		row.UserAgent = r.UserAgent()
	}
	row.Metadata = scrubAudit(meta)
	if err := a.repo.Insert(row); err != nil {
		log.Printf("audit %s: %v", action, err)
	}
}

func scrubAudit(meta map[string]any) map[string]any {
	defer telemetry.Step("service.scrubAudit")()
	out := map[string]any{}
	for key, value := range meta {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "private") {
			continue
		}
		out[key] = value
	}
	return out
}

func (a *AuditLog) List(action, actorID string, since time.Time) ([]repository.AuditRow, error) {
	defer telemetry.Step("service.AuditLog.List")()
	if a == nil || a.repo == nil {
		return nil, nil
	}
	return a.repo.List(action, actorID, since)
}
