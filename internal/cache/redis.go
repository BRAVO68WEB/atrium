package cache

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

// NewClient opens Redis. addr may be host:port or a redis:// URL.
func NewClient(cfg config.RedisConfig) (*redis.Client, error) {
	defer telemetry.Step("cache.NewClient")()
	addr := strings.TrimSpace(cfg.Addr)
	if addr == "" {
		return nil, fmt.Errorf("redis.addr is required")
	}
	var opts *redis.Options
	var err error
	if strings.Contains(addr, "://") {
		opts, err = redis.ParseURL(addr)
		if err != nil {
			return nil, fmt.Errorf("redis.addr: %w", err)
		}
		if cfg.Username != "" {
			opts.Username = cfg.Username
		}
		if cfg.Password != "" {
			opts.Password = cfg.Password
		}
		if cfg.DB != 0 && !strings.Contains(addr, "/") {
			opts.DB = cfg.DB
		}
	} else {
		opts = &redis.Options{
			Addr:     addr,
			Username: cfg.Username,
			Password: cfg.Password,
			DB:       cfg.DB,
		}
	}
	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: %w", err)
	}
	return client, nil
}

// RedisCache stores values with a Redis TTL. Keys are prefix + ":" + key.
type RedisCache struct {
	rdb    *redis.Client
	prefix string
}

func NewRedis(rdb *redis.Client, prefix string) *RedisCache {
	defer telemetry.Step("cache.NewRedis")()
	prefix = strings.Trim(strings.TrimSpace(prefix), ":")
	if prefix == "" {
		prefix = "oauth"
	}
	return &RedisCache{rdb: rdb, prefix: prefix}
}

func (c *RedisCache) key(name string) string {
	defer telemetry.Step("cache.RedisCache.key")()
	return c.prefix + ":" + name
}

func (c *RedisCache) Get(ctx context.Context, key string) ([]byte, bool, error) {
	defer telemetry.Step("cache.RedisCache.Get")()
	raw, err := c.rdb.Get(ctx, c.key(key)).Bytes()
	if err == redis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return raw, true, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	defer telemetry.Step("cache.RedisCache.Set")()
	return c.rdb.Set(ctx, c.key(key), value, ttl).Err()
}

func (c *RedisCache) Add(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	defer telemetry.Step("cache.RedisCache.Add")()
	return c.rdb.SetNX(ctx, c.key(key), value, ttl).Result()
}
