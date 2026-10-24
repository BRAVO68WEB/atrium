package service

import (
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type SessionService struct {
	repo     *repository.SessionRepository
	lifetime time.Duration
}

func NewSessionService(repo *repository.SessionRepository, lifetime time.Duration) *SessionService {
	defer telemetry.Step("service.NewSessionService")()
	return &SessionService{repo: repo, lifetime: lifetime}
}

func (s *SessionService) duration() time.Duration {
	defer telemetry.Step("service.SessionService.duration")()
	if s == nil || s.lifetime <= 0 {
		return 8 * time.Hour
	}
	return s.lifetime
}

func (s *SessionService) Start(userID, username, userAgent, ip string, mfaVerified bool) (*models.BrowserSession, error) {
	defer telemetry.Step("service.SessionService.Start")()
	now := time.Now()
	sess := &models.BrowserSession{
		ID:          uuid.NewString(),
		UserID:      userID,
		Username:    username,
		AuthTime:    now,
		MFAVerified: mfaVerified,
		UserAgent:   userAgent,
		IP:          ip,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.duration()),
	}
	if err := s.repo.Create(sess); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *SessionService) Get(id string) (*models.BrowserSession, error) {
	defer telemetry.Step("service.SessionService.Get")()
	if s == nil || id == "" {
		return nil, sql.ErrNoRows
	}
	sess, err := s.repo.Get(id)
	if err != nil {
		return nil, err
	}
	if !s.repo.Active(sess, time.Now()) {
		return nil, sql.ErrNoRows
	}
	return sess, nil
}

func (s *SessionService) GetAny(id string) (*models.BrowserSession, error) {
	defer telemetry.Step("service.SessionService.GetAny")()
	if s == nil || id == "" {
		return nil, sql.ErrNoRows
	}
	return s.repo.Get(id)
}

func (s *SessionService) MarkMFA(id string) error {
	defer telemetry.Step("service.SessionService.MarkMFA")()
	return s.repo.MarkMFA(id)
}

func (s *SessionService) Revoke(id string) error {
	defer telemetry.Step("service.SessionService.Revoke")()
	if id == "" {
		return nil
	}
	return s.repo.Revoke(id)
}

func (s *SessionService) List(userID string) ([]*models.BrowserSession, error) {
	defer telemetry.Step("service.SessionService.List")()
	return s.repo.ListByUser(userID)
}

func (s *SessionService) RevokeAllExcept(userID, exceptSID string) ([]string, error) {
	defer telemetry.Step("service.SessionService.RevokeAllExcept")()
	return s.repo.RevokeAllExcept(userID, exceptSID)
}

func (s *SessionService) RecordClient(sid, clientID string) error {
	defer telemetry.Step("service.SessionService.RecordClient")()
	return s.repo.RecordClient(sid, clientID)
}

func (s *SessionService) Clients(sid string) ([]string, error) {
	defer telemetry.Step("service.SessionService.Clients")()
	return s.repo.ListClients(sid)
}
