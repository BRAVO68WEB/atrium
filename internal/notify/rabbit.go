package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"github.com/bravo68web/oauth-impl/internal/log"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

// Rabbit publishes durable messages. A retry waits on a queue whose
// message TTL dead-letters the job back to the main queue.
type Rabbit struct {
	url      string
	exchange string
	queue    string

	mu        sync.Mutex
	conn      *amqp.Connection
	pub       *amqp.Channel
	declared  map[int64]bool
	closeOnce sync.Once
}

func NewRabbit(url, exchange, queue string) (*Rabbit, error) {
	defer telemetry.Step("notify.NewRabbit")()
	if url == "" {
		return nil, fmt.Errorf("notify.rabbitmq.url is required")
	}
	if exchange == "" {
		exchange = "oauth.notify"
	}
	if queue == "" {
		queue = "oauth.notify"
	}
	r := &Rabbit{
		url:      url,
		exchange: exchange,
		queue:    queue,
		declared: map[int64]bool{},
	}
	if err := r.connect(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rabbit) connect() error {
	conn, err := amqp.DialConfig(r.url, amqp.Config{Dial: amqp.DefaultDial(5 * time.Second), Heartbeat: 10 * time.Second})
	if err != nil {
		return fmt.Errorf("rabbitmq: %w", err)
	}
	ch, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("rabbitmq channel: %w", err)
	}
	if err := r.declareMain(ch); err != nil {
		_ = ch.Close()
		_ = conn.Close()
		return err
	}
	r.mu.Lock()
	if r.conn != nil {
		_ = r.pub.Close()
		_ = r.conn.Close()
	}
	r.conn = conn
	r.pub = ch
	r.declared = map[int64]bool{}
	r.mu.Unlock()
	return nil
}

func (r *Rabbit) declareMain(ch *amqp.Channel) error {
	if err := ch.ExchangeDeclare(r.exchange, "direct", true, false, false, false, nil); err != nil {
		return fmt.Errorf("rabbitmq exchange: %w", err)
	}
	if _, err := ch.QueueDeclare(r.queue, true, false, false, false, nil); err != nil {
		return fmt.Errorf("rabbitmq queue: %w", err)
	}
	if err := ch.QueueBind(r.queue, "notify", r.exchange, false, nil); err != nil {
		return fmt.Errorf("rabbitmq bind: %w", err)
	}
	return nil
}

func (r *Rabbit) ensureDelay(ch *amqp.Channel, delay time.Duration) (string, error) {
	ms := delay.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	name := fmt.Sprintf("%s.wait.%d", r.queue, ms)
	if r.declared[ms] {
		return name, nil
	}
	args := amqp.Table{
		"x-message-ttl":             ms,
		"x-dead-letter-exchange":    r.exchange,
		"x-dead-letter-routing-key": "notify",
	}
	if _, err := ch.QueueDeclare(name, true, false, false, false, args); err != nil {
		return "", fmt.Errorf("rabbitmq delay queue: %w", err)
	}
	if err := ch.QueueBind(name, name, r.exchange, false, nil); err != nil {
		return "", fmt.Errorf("rabbitmq delay bind: %w", err)
	}
	r.declared[ms] = true
	return name, nil
}

func (r *Rabbit) Publish(ctx context.Context, job Job, delay time.Duration) error {
	defer telemetry.Step("notify.Rabbit.Publish")()
	if delay < 0 {
		delay = 0
	}
	job = prepare(job)
	raw, err := json.Marshal(job)
	if err != nil {
		return err
	}
	r.mu.Lock()
	ch := r.pub
	r.mu.Unlock()
	if ch == nil {
		if err := r.connect(); err != nil {
			return err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pub == nil {
		return fmt.Errorf("rabbitmq publisher is closed")
	}
	key := "notify"
	if delay > 0 {
		name, err := r.ensureDelay(r.pub, delay)
		if err != nil {
			return err
		}
		key = name
	}
	return r.pub.PublishWithContext(ctx, r.exchange, key, false, false, amqp.Publishing{
		ContentType:  "application/json",
		DeliveryMode: amqp.Persistent,
		Body:         raw,
	})
}

func (r *Rabbit) Consume(ctx context.Context, handle Handler, delays []time.Duration) error {
	defer telemetry.Step("notify.Rabbit.Consume")()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		err := r.consumeOnce(ctx, handle, delays)
		if err == nil || ctx.Err() != nil {
			return nil
		}
		log.Warn("notify rabbitmq", "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Second):
		}
	}
}

func (r *Rabbit) consumeOnce(ctx context.Context, handle Handler, delays []time.Duration) error {
	r.mu.Lock()
	conn := r.conn
	r.mu.Unlock()
	if conn == nil || conn.IsClosed() {
		if err := r.connect(); err != nil {
			return err
		}
		r.mu.Lock()
		conn = r.conn
		r.mu.Unlock()
	}
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer func() { _ = ch.Close() }()
	if err := ch.Qos(8, 0, false); err != nil {
		return err
	}
	msgs, err := ch.Consume(r.queue, "", false, false, false, false, nil)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-msgs:
			if !ok {
				return fmt.Errorf("rabbitmq consumer closed")
			}
			var job Job
			if err := json.Unmarshal(msg.Body, &job); err != nil {
				_ = msg.Ack(false)
				continue
			}
			job = prepare(job)
			if err := Settle(ctx, r, delays, job, handle); err != nil {
				_ = msg.Nack(false, true)
				continue
			}
			_ = msg.Ack(false)
		}
	}
}

func (r *Rabbit) Close() error {
	defer telemetry.Step("notify.Rabbit.Close")()
	var err error
	r.closeOnce.Do(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.pub != nil {
			err = r.pub.Close()
		}
		if r.conn != nil {
			if cerr := r.conn.Close(); err == nil {
				err = cerr
			}
		}
	})
	return err
}
