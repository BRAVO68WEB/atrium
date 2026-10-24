package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/mailer"
	"github.com/bravo68web/oauth-impl/internal/notify"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

// Outbox accepts a delivery after the request that caused it.
type Outbox interface {
	Publish(ctx context.Context, job notify.Job, delay time.Duration) error
}

// DispatchNotify is the consumer for webhook and mail jobs.
func DispatchNotify(hooks *WebhookDispatcher, mail mailer.Mailer) notify.Handler {
	defer telemetry.Step("service.DispatchNotify")()
	return func(ctx context.Context, job notify.Job) error {
		defer telemetry.Step("service.dispatchNotify")()
		switch job.Kind {
		case notify.KindWebhook:
			return dispatchWebhook(hooks, job)
		case notify.KindMail:
			return dispatchMail(mail, job)
		default:
			return fmt.Errorf("%w: kind %s", notify.ErrPermanent, job.Kind)
		}
	}
}

func dispatchWebhook(hooks *WebhookDispatcher, job notify.Job) error {
	if hooks == nil || job.HookID == "" || job.Body == "" {
		return fmt.Errorf("%w: incomplete webhook", notify.ErrPermanent)
	}
	hook, err := hooks.Get(job.HookID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if hook == nil || !hook.Wants(job.Event) {
		return nil
	}
	err = hooks.post(hook, job.Event, []byte(job.Body))
	if err == nil {
		return nil
	}
	var status int
	if _, scanErr := fmt.Sscanf(err.Error(), "receiver returned %d", &status); scanErr == nil {
		if status == 429 || status == 408 || status >= 500 {
			return err
		}
		return fmt.Errorf("%w: %s", notify.ErrPermanent, err.Error())
	}
	return err
}

func dispatchMail(mail mailer.Mailer, job notify.Job) error {
	if mail == nil || !mail.Enabled() {
		return fmt.Errorf("%w: mailer disabled", notify.ErrPermanent)
	}
	if strings.TrimSpace(job.To) == "" || strings.TrimSpace(job.Subject) == "" {
		return fmt.Errorf("%w: incomplete mail", notify.ErrPermanent)
	}
	err := mail.Send(job.To, job.Subject, job.Text)
	if err == nil {
		return nil
	}
	if permanentMail(err) {
		return fmt.Errorf("%w: %s", notify.ErrPermanent, err.Error())
	}
	return err
}

func permanentMail(err error) bool {
	msg := err.Error()
	if strings.Contains(msg, "invalid mail address") || strings.Contains(msg, "mail subject is empty") {
		return true
	}
	for _, code := range []string{"500", "501", "550", "551", "552", "553", "554"} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}
