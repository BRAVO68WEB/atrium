package notify

import (
	"context"
	"sync"
	"time"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type memItem struct {
	ready time.Time
	job   Job
}

// Memory keeps jobs in the process. A restart drops them.
type Memory struct {
	mu     sync.Mutex
	items  []memItem
	wake   chan struct{}
	closed bool
}

func NewMemory() *Memory {
	defer telemetry.Step("notify.NewMemory")()
	return &Memory{wake: make(chan struct{}, 1)}
}

func (m *Memory) Publish(ctx context.Context, job Job, delay time.Duration) error {
	defer telemetry.Step("notify.Memory.Publish")()
	if err := ctx.Err(); err != nil {
		return err
	}
	if delay < 0 {
		delay = 0
	}
	job = prepare(job)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return context.Canceled
	}
	m.items = append(m.items, memItem{ready: time.Now().Add(delay), job: job})
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}

func (m *Memory) Consume(ctx context.Context, handle Handler, delays []time.Duration) error {
	defer telemetry.Step("notify.Memory.Consume")()
	for {
		job, ok, wait := m.next()
		if ok {
			if err := Settle(ctx, m, delays, job, handle); err != nil {
				_ = m.Publish(ctx, job, time.Second)
			}
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-m.wake:
			timer.Stop()
		case <-timer.C:
		}
		m.mu.Lock()
		closed := m.closed
		m.mu.Unlock()
		if closed {
			return nil
		}
	}
}

func (m *Memory) next() (Job, bool, time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return Job{}, false, time.Hour
	}
	now := time.Now()
	best := -1
	var soonest time.Time
	for i, item := range m.items {
		if !item.ready.After(now) {
			best = i
			break
		}
		if best < 0 && (soonest.IsZero() || item.ready.Before(soonest)) {
			soonest = item.ready
		}
	}
	if best >= 0 {
		job := m.items[best].job
		m.items = append(m.items[:best], m.items[best+1:]...)
		return job, true, 0
	}
	if soonest.IsZero() {
		return Job{}, false, time.Hour
	}
	return Job{}, false, time.Until(soonest)
}

func (m *Memory) Close() error {
	defer telemetry.Step("notify.Memory.Close")()
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
	return nil
}
