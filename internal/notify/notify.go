// Package notify delivers webhook and mail jobs after the HTTP response.
// A failed attempt is queued again. The delays are 1s, 5s, 30s, 2m, and
// 10m. A permanent failure is dropped. memory loses the queue on exit.
// redis and rabbitmq keep it across a restart.
package notify

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bravo68web/oauth-impl/internal/log"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/google/uuid"
)

const (
	KindWebhook = "webhook"
	KindMail    = "mail"
)

// ErrPermanent marks a job that must not be retried.
var ErrPermanent = errors.New("permanent notify failure")

// DefaultDelays is the wait before attempt 2, 3, 4, 5, and 6.
var DefaultDelays = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
	2 * time.Minute,
	10 * time.Minute,
}

// Job is one delivery. Body is the webhook JSON. Mail uses To, Subject, and Text.
type Job struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Attempt int    `json:"attempt"`
	HookID  string `json:"hook_id,omitempty"`
	Event   string `json:"event,omitempty"`
	Body    string `json:"body,omitempty"`
	To      string `json:"to,omitempty"`
	Subject string `json:"subject,omitempty"`
	Text    string `json:"text,omitempty"`
}

// Handler runs one attempt. A nil error acknowledges the job.
// ErrPermanent acknowledges it and drops it. Any other error asks the
// queue to try again later.
type Handler func(context.Context, Job) error

// Queue stores jobs and runs a consumer.
type Queue interface {
	Publish(ctx context.Context, job Job, delay time.Duration) error
	Consume(ctx context.Context, handle Handler, delays []time.Duration) error
	Close() error
}

func prepare(job Job) Job {
	if job.ID == "" {
		job.ID = uuid.NewString()
	}
	if job.Attempt <= 0 {
		job.Attempt = 1
	}
	return job
}

// Settle runs one attempt and publishes the next delay when the handler
// asks for a retry. A nil return acknowledges the current copy.
func Settle(ctx context.Context, pub Queue, delays []time.Duration, job Job, handle Handler) error {
	defer telemetry.Step("notify.Settle")()
	if handle == nil {
		return fmt.Errorf("notify handler is required")
	}
	err := handle(ctx, job)
	if err == nil || errors.Is(err, ErrPermanent) {
		if err != nil {
			log.Warn("notify dropped", "kind", job.Kind, "id", job.ID, "attempt", job.Attempt, "err", err)
		}
		return nil
	}
	delay, ok := nextDelay(delays, job.Attempt)
	if !ok {
		log.Warn("notify gave up", "kind", job.Kind, "id", job.ID, "attempt", job.Attempt, "err", err)
		return nil
	}
	job.Attempt++
	if pubErr := pub.Publish(ctx, job, delay); pubErr != nil {
		return pubErr
	}
	return nil
}

func nextDelay(delays []time.Duration, attempt int) (time.Duration, bool) {
	if len(delays) == 0 {
		delays = DefaultDelays
	}
	idx := attempt - 1
	if idx < 0 || idx >= len(delays) {
		return 0, false
	}
	return delays[idx], true
}
