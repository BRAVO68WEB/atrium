package notify

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const claimVisibility = 30 * time.Second

// claimScript removes one due job and stores it under a claim token.
const claimScript = `
local items = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', '0', '1')
if #items == 0 then
  return ''
end
local job = items[1]
redis.call('ZREM', KEYS[1], job)
redis.call('SET', KEYS[3], job, 'PX', ARGV[2])
redis.call('ZADD', KEYS[2], tonumber(ARGV[1]) + tonumber(ARGV[2]), ARGV[3])
return job
`

// reclaimScript returns expired claims to the due set.
const reclaimScript = `
local tokens = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', ARGV[1], 'LIMIT', '0', '20')
local n = 0
for _, token in ipairs(tokens) do
  local key = ARGV[2] .. token
  local job = redis.call('GET', key)
  if job then
    redis.call('ZADD', KEYS[1], ARGV[1], job)
    redis.call('DEL', key)
  end
  redis.call('ZREM', KEYS[2], token)
  n = n + 1
end
return n
`

// Redis stores due jobs in a sorted set. A claim expires after 30 seconds
// so a crashed worker does not take the job with it.
type Redis struct {
	rdb        *redis.Client
	prefix     string
	visibility time.Duration
}

func NewRedis(rdb *redis.Client, prefix string) *Redis {
	defer telemetry.Step("notify.NewRedis")()
	prefix = strings.Trim(strings.TrimSpace(prefix), ":")
	if prefix == "" {
		prefix = "oauth"
	}
	return &Redis{rdb: rdb, prefix: prefix, visibility: claimVisibility}
}

func (q *Redis) dueKey() string   { return q.prefix + ":notify:due" }
func (q *Redis) claimKey() string { return q.prefix + ":notify:claim" }
func (q *Redis) jobPrefix() string {
	return q.prefix + ":notify:job:"
}

func (q *Redis) Publish(ctx context.Context, job Job, delay time.Duration) error {
	defer telemetry.Step("notify.Redis.Publish")()
	if delay < 0 {
		delay = 0
	}
	job = prepare(job)
	raw, err := json.Marshal(job)
	if err != nil {
		return err
	}
	score := float64(time.Now().Add(delay).UnixMilli())
	return q.rdb.ZAdd(ctx, q.dueKey(), redis.Z{Score: score, Member: string(raw)}).Err()
}

func (q *Redis) Consume(ctx context.Context, handle Handler, delays []time.Duration) error {
	defer telemetry.Step("notify.Redis.Consume")()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := q.reclaim(ctx); err != nil {
			return err
		}
		raw, token, err := q.claim(ctx)
		if err != nil {
			return err
		}
		if raw == "" {
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		}
		var job Job
		if err := json.Unmarshal([]byte(raw), &job); err != nil {
			_ = q.ack(ctx, token)
			continue
		}
		if err := Settle(ctx, q, delays, job, handle); err != nil {
			continue
		}
		if err := q.ack(ctx, token); err != nil {
			return err
		}
	}
}

func (q *Redis) claim(ctx context.Context) (string, string, error) {
	token := uuid.NewString()
	now := time.Now().UnixMilli()
	vis := q.visibility.Milliseconds()
	if vis < 1 {
		vis = claimVisibility.Milliseconds()
	}
	raw, err := q.rdb.Eval(ctx, claimScript, []string{q.dueKey(), q.claimKey(), q.jobPrefix() + token}, now, vis, token).Text()
	if err == redis.Nil {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	return raw, token, nil
}

func (q *Redis) reclaim(ctx context.Context) error {
	now := time.Now().UnixMilli()
	err := q.rdb.Eval(ctx, reclaimScript, []string{q.dueKey(), q.claimKey()}, now, q.jobPrefix()).Err()
	if err == redis.Nil {
		return nil
	}
	return err
}

func (q *Redis) ack(ctx context.Context, token string) error {
	pipe := q.rdb.TxPipeline()
	pipe.Del(ctx, q.jobPrefix()+token)
	pipe.ZRem(ctx, q.claimKey(), token)
	_, err := pipe.Exec(ctx)
	return err
}

func (q *Redis) Close() error {
	defer telemetry.Step("notify.Redis.Close")()
	return nil
}
