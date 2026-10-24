package telemetry

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"unicode"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const maxStatement = 512

// QuerySpan starts a database span under the current goroutine span.
// The statement keeps placeholders. Quoted literals are replaced and
// argument values are not attributes. Call the returned function with the
// query error when the operation finishes. sql.ErrNoRows is not a failure.
func QuerySpan(system, query string, nargs int) func(error) {
	if !recordingOn() {
		return func(error) {}
	}
	op := sqlOperation(query)
	ctx, end := Start(Bound(), "db."+op)
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(
		attribute.String("db.system", system),
		attribute.String("db.operation", op),
		attribute.String("db.statement", redactSQL(query)),
		attribute.Int("db.arg_count", nargs),
	)
	return func(err error) {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			span.SetStatus(codes.Error, "query failed")
		}
		end()
	}
}

// Context is the request context bound to this goroutine, or Background.
func Context() context.Context {
	return Bound()
}

func sqlOperation(query string) string {
	fields := strings.Fields(query)
	if len(fields) == 0 {
		return "exec"
	}
	switch strings.ToLower(fields[0]) {
	case "select", "insert", "update", "delete":
		return strings.ToLower(fields[0])
	default:
		return "exec"
	}
}

func redactSQL(query string) string {
	var b strings.Builder
	b.Grow(len(query))
	inString := false
	lastSpace := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if inString {
			if c == '\'' {
				if i+1 < len(query) && query[i+1] == '\'' {
					i++
					continue
				}
				inString = false
				lastSpace = false
				b.WriteString("?'")
			}
			continue
		}
		if c == '\'' {
			inString = true
			lastSpace = false
			b.WriteByte('\'')
			continue
		}
		if unicode.IsSpace(rune(c)) {
			if b.Len() == 0 || lastSpace {
				continue
			}
			b.WriteByte(' ')
			lastSpace = true
			continue
		}
		lastSpace = false
		b.WriteByte(c)
	}
	out := strings.TrimSpace(b.String())
	if len(out) > maxStatement {
		return out[:maxStatement]
	}
	return out
}

func traceString(key, value string) attribute.KeyValue {
	return attribute.String(key, value)
}
