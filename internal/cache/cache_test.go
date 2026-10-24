package cache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestMemoryCacheExpiresAndRejectsReplay(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	if err := store.Set(ctx, "cimd:a", []byte("doc"), time.Minute); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(ctx, "cimd:a")
	if err != nil || !ok || string(got) != "doc" {
		t.Fatalf("get = %q ok=%v err=%v", got, ok, err)
	}
	store.mu.Lock()
	entry := store.items["cimd:a"]
	entry.expires = time.Now().Add(-time.Second)
	store.items["cimd:a"] = entry
	store.mu.Unlock()
	if _, ok, err := store.Get(ctx, "cimd:a"); err != nil || ok {
		t.Fatalf("expired get ok=%v err=%v", ok, err)
	}

	added, err := store.Add(ctx, "dpop:jti:1", []byte("1"), time.Minute)
	if err != nil || !added {
		t.Fatalf("first add = %v %v", added, err)
	}
	added, err = store.Add(ctx, "dpop:jti:1", []byte("1"), time.Minute)
	if err != nil || added {
		t.Fatalf("replay add = %v %v", added, err)
	}
}

func TestRedisCacheTTLAndAdd(t *testing.T) {
	ctx := context.Background()
	srv := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewRedis(rdb, "oauth")

	if err := store.Set(ctx, "cimd:a", []byte("doc"), time.Minute); err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Get(ctx, "cimd:a")
	if err != nil || !ok || string(got) != "doc" {
		t.Fatalf("get = %q ok=%v err=%v", got, ok, err)
	}
	srv.FastForward(2 * time.Minute)
	if _, ok, err := store.Get(ctx, "cimd:a"); err != nil || ok {
		t.Fatalf("expired get ok=%v err=%v", ok, err)
	}

	added, err := store.Add(ctx, "dpop:jti:1", []byte("1"), time.Minute)
	if err != nil || !added {
		t.Fatalf("first add = %v %v", added, err)
	}
	added, err = store.Add(ctx, "dpop:jti:1", []byte("1"), time.Minute)
	if err != nil || added {
		t.Fatalf("replay add = %v %v", added, err)
	}
}

func TestMemoryCacheDropsExpiredKeys(t *testing.T) {
	ctx := context.Background()
	store := NewMemory()
	for i := 0; i < memorySweepAt; i++ {
		if err := store.Set(ctx, fmt.Sprintf("dpop:jti:%d", i), []byte("1"), time.Millisecond); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(5 * time.Millisecond)
	if err := store.Set(ctx, "dpop:jti:fresh", []byte("1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	left := len(store.items)
	_, fresh := store.items["dpop:jti:fresh"]
	store.mu.Unlock()
	if !fresh || left != 1 {
		t.Fatalf("map has %d keys, fresh=%v", left, fresh)
	}
}
