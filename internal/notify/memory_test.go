package notify

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryRetriesThenAcks(t *testing.T) {
	q := NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		_ = q.Consume(ctx, func(context.Context, Job) error {
			if calls.Add(1) < 3 {
				return fmt.Errorf("not yet")
			}
			close(done)
			return nil
		}, []time.Duration{15 * time.Millisecond, 15 * time.Millisecond})
	}()
	if err := q.Publish(context.Background(), Job{Kind: KindMail, To: "ada@example.com"}, 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("job was not delivered")
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestMemoryDropsPermanentFailure(t *testing.T) {
	q := NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	go func() {
		_ = q.Consume(ctx, func(context.Context, Job) error {
			calls.Add(1)
			return fmt.Errorf("%w: receiver returned 404", ErrPermanent)
		}, []time.Duration{10 * time.Millisecond})
	}()
	if err := q.Publish(context.Background(), Job{Kind: KindWebhook, HookID: "hook"}, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNextDelayStopsAfterSchedule(t *testing.T) {
	delays := []time.Duration{time.Second, 5 * time.Second}
	if d, ok := nextDelay(delays, 1); !ok || d != time.Second {
		t.Fatalf("first delay %s %v", d, ok)
	}
	if d, ok := nextDelay(delays, 2); !ok || d != 5*time.Second {
		t.Fatalf("second delay %s %v", d, ok)
	}
	if _, ok := nextDelay(delays, 3); ok {
		t.Fatal("expected the schedule to end")
	}
	if !errors.Is(fmt.Errorf("%w: gone", ErrPermanent), ErrPermanent) {
		t.Fatal("permanent errors must unwrap")
	}
}
