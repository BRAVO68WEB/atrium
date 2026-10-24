package telemetry

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/otel/trace"
)

// The request goroutine is bound to the active span for the life of the
// handler. Repository and helper functions do not take a context, so a
// query or a nested call on that same goroutine becomes a child of whatever
// span is current. A goroutine started with `go` does not inherit the
// binding. Pass that goroutine a context and call Start from it.

var (
	recording atomic.Bool
	binds     atomic.Int32
	bindMu    sync.Mutex
	bound     = map[int64]context.Context{}
)

var nop = func() {}

// SetRecording turns helper and query spans on. Setup does this when
// telemetry is enabled. Tests use it with an in-memory exporter.
func SetRecording(on bool) {
	recording.Store(on)
}

func recordingOn() bool {
	return recording.Load()
}

// Bind makes ctx the current span context for this goroutine. The returned
// function restores the previous context.
func Bind(ctx context.Context) func() {
	if ctx == nil {
		ctx = context.Background()
	}
	id := goid()
	bindMu.Lock()
	prev, ok := bound[id]
	bound[id] = ctx
	bindMu.Unlock()
	binds.Add(1)
	return func() {
		bindMu.Lock()
		if ok {
			bound[id] = prev
		} else {
			delete(bound, id)
		}
		bindMu.Unlock()
		binds.Add(-1)
	}
}

// Bound is the span context for this goroutine, or Background when the
// request did not bind one.
func Bound() context.Context {
	if binds.Load() == 0 {
		return context.Background()
	}
	id := goid()
	bindMu.Lock()
	ctx := bound[id]
	bindMu.Unlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// Step starts a child span named name under the current goroutine span.
// The deferred call ends the span. With recording off this is one flag check.
func Step(name string) func() {
	if !recordingOn() {
		return nop
	}
	_, end := Start(Bound(), name)
	return end
}

// Start starts a child span. A bound span on this goroutine is the parent
// even when ctx itself has no span, and ctx still controls cancellation.
func Start(ctx context.Context, name string) (context.Context, func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	if parent := Bound(); trace.SpanContextFromContext(parent).IsValid() {
		ctx = trace.ContextWithSpan(ctx, trace.SpanFromContext(parent))
	}
	ctx, span := Tracer().Start(ctx, name)
	if !span.IsRecording() {
		return ctx, nop
	}
	undo := Bind(ctx)
	return ctx, func() {
		span.End()
		undo()
	}
}

// Interaction records which screen the authorize request is about to show,
// or that the request completed without one.
func Interaction(kind string) {
	Event("oauth.interaction", "oauth.interaction", kind)
}

// Event adds a timestamped mark on the current span.
func Event(name, key, value string) {
	if !recordingOn() {
		return
	}
	span := trace.SpanFromContext(Bound())
	if !span.IsRecording() {
		return
	}
	span.AddEvent(name, trace.WithAttributes(traceString(key, value)))
}

func goid() int64 {
	var buf [72]byte
	n := runtime.Stack(buf[:], false)
	// "goroutine 123 ["
	s := buf[:n]
	const prefix = "goroutine "
	if len(s) < len(prefix) {
		return 0
	}
	s = s[len(prefix):]
	var id int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		id = id*10 + int64(c-'0')
	}
	return id
}
