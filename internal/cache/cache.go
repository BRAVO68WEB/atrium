package cache

import (
	"context"
	"sync"
	"time"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

// Cache stores short-lived values. Add reports whether the key was newly stored.
type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Add(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
}

type memoryEntry struct {
	value   []byte
	expires time.Time
}

// memorySweepAt is the map size that triggers a drop of expired keys.
// DPoP and XAA only call Add, so an expired key stays until that same
// key is written again. A busy process would keep every proof forever.
const memorySweepAt = 1024

// MemoryCache is the default cache. A zero TTL does not expire.
type MemoryCache struct {
	mu    sync.Mutex
	items map[string]memoryEntry
}

func NewMemory() *MemoryCache {
	defer telemetry.Step("cache.NewMemory")()
	return &MemoryCache{items: map[string]memoryEntry{}}
}

func (c *MemoryCache) Get(_ context.Context, key string) ([]byte, bool, error) {
	defer telemetry.Step("cache.MemoryCache.Get")()
	if c == nil {
		return nil, false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.items[key]
	if !ok || expired(entry.expires) {
		delete(c.items, key)
		return nil, false, nil
	}
	return append([]byte(nil), entry.value...), true, nil
}

func (c *MemoryCache) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	defer telemetry.Step("cache.MemoryCache.Set")()
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[key] = memoryEntry{value: append([]byte(nil), value...), expires: deadline(ttl)}
	c.sweepLocked()
	return nil
}

func (c *MemoryCache) Add(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	defer telemetry.Step("cache.MemoryCache.Add")()
	if c == nil {
		return false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.items[key]; ok && !expired(entry.expires) {
		return false, nil
	}
	c.items[key] = memoryEntry{value: append([]byte(nil), value...), expires: deadline(ttl)}
	c.sweepLocked()
	return true, nil
}

func (c *MemoryCache) sweepLocked() {
	if c == nil || len(c.items) <= memorySweepAt {
		return
	}
	for key, entry := range c.items {
		if expired(entry.expires) {
			delete(c.items, key)
		}
	}
}

func deadline(ttl time.Duration) time.Time {
	defer telemetry.Step("cache.deadline")()
	if ttl <= 0 {
		return time.Time{}
	}
	return time.Now().Add(ttl)
}

func expired(at time.Time) bool {
	defer telemetry.Step("cache.expired")()
	return !at.IsZero() && !time.Now().Before(at)
}
