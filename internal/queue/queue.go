package queue

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type AuthRequestType string

const (
	AuthRequestTypeCIBA   AuthRequestType = "ciba"
	AuthRequestTypeDevice AuthRequestType = "device"
)

type AuthRequestStatus string

const (
	StatusPending  AuthRequestStatus = "pending"
	StatusApproved AuthRequestStatus = "approved"
	StatusDenied   AuthRequestStatus = "denied"
	StatusExpired  AuthRequestStatus = "expired"
)

type AuthRequest struct {
	ID                      string            `json:"id"`
	Type                    AuthRequestType   `json:"type"`
	ClientID                string            `json:"client_id"`
	UserID                  string            `json:"user_id,omitempty"`
	BindingMessage          string            `json:"binding_message,omitempty"`
	UserCode                string            `json:"user_code,omitempty"`
	Status                  AuthRequestStatus `json:"status"`
	DeliveryMode            string            `json:"delivery_mode,omitempty"`
	Interval                int               `json:"interval"`
	ClientNotificationToken string            `json:"client_notification_token,omitempty"`
	CreatedAt               time.Time         `json:"created_at"`
	ExpiresAt               time.Time         `json:"expires_at"`
	DenialReason            string            `json:"denial_reason,omitempty"`
}

type Queue interface {
	Enqueue(req *AuthRequest) error
	Dequeue() (*AuthRequest, error)
	GetByID(id string) (*AuthRequest, error)
	GetPending() ([]*AuthRequest, error)
	Approve(id string, userID string) error
	Deny(id string, reason string) error
	Count() int
	StartCleanup(ctx context.Context, interval time.Duration)
	Poll(ctx context.Context, interval time.Duration) <-chan *AuthRequest
}

type MemoryQueue struct {
	mu       sync.RWMutex
	requests map[string]*AuthRequest
	pending  chan string
	maxSize  int
}

func NewMemoryQueue(maxSize int) *MemoryQueue {
	defer telemetry.Step("queue.NewMemoryQueue")()
	return &MemoryQueue{
		requests: make(map[string]*AuthRequest),
		pending:  make(chan string, maxSize),
		maxSize:  maxSize,
	}
}

func (q *MemoryQueue) Enqueue(req *AuthRequest) error {
	defer telemetry.Step("queue.MemoryQueue.Enqueue")()
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.requests) >= q.maxSize {
		return fmt.Errorf("queue is full (max size: %d)", q.maxSize)
	}

	if _, exists := q.requests[req.ID]; exists {
		return fmt.Errorf("request already exists: %s", req.ID)
	}

	q.requests[req.ID] = req

	select {
	case q.pending <- req.ID:
	default:
		return fmt.Errorf("pending channel is full")
	}

	return nil
}

func (q *MemoryQueue) Dequeue() (*AuthRequest, error) {
	defer telemetry.Step("queue.MemoryQueue.Dequeue")()
	q.mu.RLock()
	defer q.mu.RUnlock()

	for _, req := range q.requests {
		if req.Status == StatusPending && time.Now().Before(req.ExpiresAt) {
			return req, nil
		}
	}

	return nil, fmt.Errorf("no pending requests available")
}

func (q *MemoryQueue) GetByID(id string) (*AuthRequest, error) {
	defer telemetry.Step("queue.MemoryQueue.GetByID")()
	q.mu.RLock()
	defer q.mu.RUnlock()

	req, exists := q.requests[id]
	if !exists {
		return nil, fmt.Errorf("request not found: %s", id)
	}

	return req, nil
}

func (q *MemoryQueue) GetPending() ([]*AuthRequest, error) {
	defer telemetry.Step("queue.MemoryQueue.GetPending")()
	q.mu.RLock()
	defer q.mu.RUnlock()

	var pending []*AuthRequest
	for _, req := range q.requests {
		if req.Status == StatusPending && time.Now().Before(req.ExpiresAt) {
			pending = append(pending, req)
		}
	}

	return pending, nil
}

func (q *MemoryQueue) Approve(id string, userID string) error {
	defer telemetry.Step("queue.MemoryQueue.Approve")()
	q.mu.Lock()
	defer q.mu.Unlock()

	req, exists := q.requests[id]
	if !exists {
		return fmt.Errorf("request not found: %s", id)
	}

	if req.Status != StatusPending {
		return fmt.Errorf("request is not pending: %s (status: %s)", id, req.Status)
	}

	if time.Now().After(req.ExpiresAt) {
		req.Status = StatusExpired
		return fmt.Errorf("request has expired: %s", id)
	}

	req.Status = StatusApproved
	req.UserID = userID
	return nil
}

func (q *MemoryQueue) Deny(id string, reason string) error {
	defer telemetry.Step("queue.MemoryQueue.Deny")()
	q.mu.Lock()
	defer q.mu.Unlock()

	req, exists := q.requests[id]
	if !exists {
		return fmt.Errorf("request not found: %s", id)
	}

	if req.Status != StatusPending {
		return fmt.Errorf("request is not pending: %s (status: %s)", id, req.Status)
	}

	req.Status = StatusDenied
	req.DenialReason = reason
	return nil
}

func (q *MemoryQueue) Count() int {
	defer telemetry.Step("queue.MemoryQueue.Count")()
	q.mu.RLock()
	defer q.mu.RUnlock()

	count := 0
	for _, req := range q.requests {
		if req.Status == StatusPending && time.Now().Before(req.ExpiresAt) {
			count++
		}
	}
	return count
}

func (q *MemoryQueue) StartCleanup(ctx context.Context, interval time.Duration) {
	defer telemetry.Step("queue.MemoryQueue.StartCleanup")()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			q.cleanup()
		}
	}
}

func (q *MemoryQueue) cleanup() {
	defer telemetry.Step("queue.MemoryQueue.cleanup")()
	q.mu.Lock()
	defer q.mu.Unlock()

	now := time.Now()
	for id, req := range q.requests {
		if now.After(req.ExpiresAt) {
			req.Status = StatusExpired
			delete(q.requests, id)
		}
	}
}

func (q *MemoryQueue) Poll(ctx context.Context, interval time.Duration) <-chan *AuthRequest {
	defer telemetry.Step("queue.MemoryQueue.Poll")()
	ch := make(chan *AuthRequest)

	go func() {
		defer close(ch)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				pending, err := q.GetPending()
				if err != nil {
					continue
				}
				for _, req := range pending {
					select {
					case ch <- req:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return ch
}

func (q *MemoryQueue) WaitForApproval(ctx context.Context, id string, timeout time.Duration) (*AuthRequest, error) {
	defer telemetry.Step("queue.MemoryQueue.WaitForApproval")()
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timeout waiting for approval")
			}

			req, err := q.GetByID(id)
			if err != nil {
				return nil, err
			}

			switch req.Status {
			case StatusApproved:
				return req, nil
			case StatusDenied:
				return req, fmt.Errorf("request denied: %s", req.DenialReason)
			case StatusExpired:
				return req, fmt.Errorf("request expired")
			}
		}
	}
}
