// Package background runs work after the HTTP handler has returned.
// Wait blocks shutdown until those tasks finish or the wait times out.
package background

import (
	"sync"
	"time"

	"github.com/bravo68web/atrium/internal/log"
)

const waitTimeout = 20 * time.Second

var wg sync.WaitGroup

// Go runs fn on a new goroutine. A panic in fn is logged and does not
// reach the caller.
func Go(fn func()) {
	if fn == nil {
		return
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			if rec := recover(); rec != nil {
				log.Error("background task", "err", rec)
			}
		}()
		fn()
	}()
}

// Wait returns when every task started with Go has finished, or after
// 20 seconds. A stuck SMTP or webhook call does not hold process exit open.
func Wait() {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	timer := time.NewTimer(waitTimeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
		log.Warn("background work still running at shutdown")
	}
}
