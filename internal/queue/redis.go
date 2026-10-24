package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

const transitionScript = `
local raw = redis.call('GET', KEYS[1])
if not raw then
  return 'missing'
end
if string.find(raw, '"status":"pending"', 1, true) == nil then
  return 'not_pending'
end
local ttl = redis.call('PTTL', KEYS[1])
if not ttl or ttl <= 0 then
  return 'expired'
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ttl)
return 'ok'
`

const enqueueScript = `
if redis.call('EXISTS', KEYS[1]) == 1 then
  return 'exists'
end
local n = redis.call('ZCOUNT', KEYS[2], ARGV[3], '+inf')
if tonumber(n) >= tonumber(ARGV[4]) then
  return 'full'
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[5])
return 'ok'
`

// RedisQueue stores auth requests until ExpiresAt. Approve and Deny are one Redis script.
type RedisQueue struct {
	rdb        *redis.Client
	prefix     string
	maxPending int
}

func NewRedis(rdb *redis.Client, prefix string, maxPending int) *RedisQueue {
	defer telemetry.Step("queue.NewRedis")()
	prefix = strings.Trim(strings.TrimSpace(prefix), ":")
	if prefix == "" {
		prefix = "oauth"
	}
	return &RedisQueue{rdb: rdb, prefix: prefix, maxPending: maxPending}
}

func (q *RedisQueue) itemKey(id string) string {
	defer telemetry.Step("queue.RedisQueue.itemKey")()
	return q.prefix + ":q:" + id
}

func (q *RedisQueue) expKey() string {
	defer telemetry.Step("queue.RedisQueue.expKey")()
	return q.prefix + ":q:exp"
}

type queueRecord struct {
	ID                      string            `json:"id"`
	Type                    AuthRequestType   `json:"type"`
	ClientID                string            `json:"client_id"`
	UserID                  string            `json:"user_id"`
	BindingMessage          string            `json:"binding_message"`
	UserCode                string            `json:"user_code"`
	Status                  AuthRequestStatus `json:"status"`
	DeliveryMode            string            `json:"delivery_mode"`
	Interval                int               `json:"interval"`
	ClientNotificationToken string            `json:"client_notification_token"`
	CreatedAt               time.Time         `json:"created_at"`
	ExpiresAt               time.Time         `json:"expires_at"`
	DenialReason            string            `json:"denial_reason"`
}

func recordFrom(req *AuthRequest) queueRecord {
	defer telemetry.Step("queue.recordFrom")()
	return queueRecord{
		ID: req.ID, Type: req.Type, ClientID: req.ClientID, UserID: req.UserID,
		BindingMessage: req.BindingMessage, UserCode: req.UserCode, Status: req.Status,
		DeliveryMode: req.DeliveryMode, Interval: req.Interval,
		ClientNotificationToken: req.ClientNotificationToken,
		CreatedAt:               req.CreatedAt, ExpiresAt: req.ExpiresAt, DenialReason: req.DenialReason,
	}
}

func (rec queueRecord) request() *AuthRequest {
	defer telemetry.Step("queue.queueRecord.request")()
	return &AuthRequest{
		ID: rec.ID, Type: rec.Type, ClientID: rec.ClientID, UserID: rec.UserID,
		BindingMessage: rec.BindingMessage, UserCode: rec.UserCode, Status: rec.Status,
		DeliveryMode: rec.DeliveryMode, Interval: rec.Interval,
		ClientNotificationToken: rec.ClientNotificationToken,
		CreatedAt:               rec.CreatedAt, ExpiresAt: rec.ExpiresAt, DenialReason: rec.DenialReason,
	}
}

func (q *RedisQueue) Enqueue(req *AuthRequest) error {
	defer telemetry.Step("queue.RedisQueue.Enqueue")()
	if req == nil || req.ID == "" {
		return fmt.Errorf("request id is required")
	}
	ttl := time.Until(req.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("request has expired: %s", req.ID)
	}
	raw, err := json.Marshal(recordFrom(req))
	if err != nil {
		return err
	}
	ctx := context.Background()
	score := strconv.FormatInt(req.ExpiresAt.UnixMilli(), 10)
	status, err := q.rdb.Eval(ctx, enqueueScript, []string{q.itemKey(req.ID), q.expKey()},
		string(raw), ttl.Milliseconds(), score, q.maxPending, req.ID).Text()
	if err != nil {
		return err
	}
	switch status {
	case "ok":
		return nil
	case "exists":
		return fmt.Errorf("request already exists: %s", req.ID)
	case "full":
		return fmt.Errorf("queue is full (max size: %d)", q.maxPending)
	default:
		return fmt.Errorf("enqueue %s", status)
	}
}

func (q *RedisQueue) load(ctx context.Context, id string) (*AuthRequest, error) {
	defer telemetry.Step("queue.RedisQueue.load")()
	raw, err := q.rdb.Get(ctx, q.itemKey(id)).Bytes()
	if err == redis.Nil {
		_ = q.rdb.ZRem(ctx, q.expKey(), id).Err()
		return nil, fmt.Errorf("request not found: %s", id)
	}
	if err != nil {
		return nil, err
	}
	var rec queueRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return rec.request(), nil
}

func (q *RedisQueue) GetByID(id string) (*AuthRequest, error) {
	defer telemetry.Step("queue.RedisQueue.GetByID")()
	return q.load(context.Background(), id)
}

func (q *RedisQueue) Dequeue() (*AuthRequest, error) {
	defer telemetry.Step("queue.RedisQueue.Dequeue")()
	pending, err := q.GetPending()
	if err != nil {
		return nil, err
	}
	if len(pending) == 0 {
		return nil, fmt.Errorf("no pending requests available")
	}
	return pending[0], nil
}

func (q *RedisQueue) GetPending() ([]*AuthRequest, error) {
	defer telemetry.Step("queue.RedisQueue.GetPending")()
	ctx := context.Background()
	now := strconv.FormatInt(time.Now().UnixMilli(), 10)
	ids, err := q.rdb.ZRangeArgs(ctx, redis.ZRangeArgs{
		Key: q.expKey(), Start: now, Stop: "+inf", ByScore: true,
	}).Result()
	if err != nil {
		return nil, err
	}
	out := make([]*AuthRequest, 0, len(ids))
	for _, id := range ids {
		req, err := q.load(ctx, id)
		if err != nil {
			continue
		}
		if req.Status == StatusPending && time.Now().Before(req.ExpiresAt) {
			out = append(out, req)
		}
	}
	return out, nil
}

func (q *RedisQueue) Approve(id string, userID string) error {
	defer telemetry.Step("queue.RedisQueue.Approve")()
	return q.transition(id, func(req *AuthRequest) error {
		req.Status = StatusApproved
		req.UserID = userID
		return nil
	})
}

func (q *RedisQueue) Deny(id string, reason string) error {
	defer telemetry.Step("queue.RedisQueue.Deny")()
	return q.transition(id, func(req *AuthRequest) error {
		req.Status = StatusDenied
		req.DenialReason = reason
		return nil
	})
}

func (q *RedisQueue) transition(id string, mutate func(*AuthRequest) error) error {
	defer telemetry.Step("queue.RedisQueue.transition")()
	ctx := context.Background()
	req, err := q.load(ctx, id)
	if err != nil {
		return err
	}
	if req.Status != StatusPending {
		return fmt.Errorf("request is not pending: %s (status: %s)", id, req.Status)
	}
	if !time.Now().Before(req.ExpiresAt) {
		return fmt.Errorf("request has expired: %s", id)
	}
	if err := mutate(req); err != nil {
		return err
	}
	raw, err := json.Marshal(recordFrom(req))
	if err != nil {
		return err
	}
	status, err := q.rdb.Eval(ctx, transitionScript, []string{q.itemKey(id)}, string(raw)).Text()
	if err != nil {
		return err
	}
	switch status {
	case "ok":
		return nil
	case "missing":
		return fmt.Errorf("request not found: %s", id)
	case "expired":
		return fmt.Errorf("request has expired: %s", id)
	case "not_pending":
		return fmt.Errorf("request is not pending: %s", id)
	default:
		return fmt.Errorf("queue transition %s", status)
	}
}

func (q *RedisQueue) Count() int {
	defer telemetry.Step("queue.RedisQueue.Count")()
	pending, err := q.GetPending()
	if err != nil {
		return 0
	}
	return len(pending)
}

func (q *RedisQueue) StartCleanup(ctx context.Context, interval time.Duration) {
	defer telemetry.Step("queue.RedisQueue.StartCleanup")()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := strconv.FormatInt(time.Now().UnixMilli(), 10)
			_ = q.rdb.ZRemRangeByScore(ctx, q.expKey(), "-inf", now).Err()
		}
	}
}

func (q *RedisQueue) Poll(ctx context.Context, interval time.Duration) <-chan *AuthRequest {
	defer telemetry.Step("queue.RedisQueue.Poll")()
	ch := make(chan *AuthRequest)
	go func() {
		defer close(ch)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		seen := map[string]struct{}{}
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
					if _, ok := seen[req.ID]; ok {
						continue
					}
					seen[req.ID] = struct{}{}
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
