package notify

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisRetriesAndClaimsOnce(t *testing.T) {
	srv := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	q := NewRedis(rdb, "test")
	q.visibility = 300 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		_ = q.Consume(ctx, func(context.Context, Job) error {
			n := calls.Add(1)
			if n == 1 {
				return context.DeadlineExceeded
			}
			close(done)
			return nil
		}, []time.Duration{20 * time.Millisecond})
	}()
	if err := q.Publish(context.Background(), Job{Kind: KindMail, To: "ada@example.com", Subject: "hi", Text: "hello"}, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("redis job was not retried, calls=%d", calls.Load())
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}
