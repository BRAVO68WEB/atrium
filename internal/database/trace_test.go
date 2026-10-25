package database

import (
	"context"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/telemetry"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestQuerySpanParentsUnderTheHelperAndHidesArgs(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	telemetry.SetRecording(true)
	t.Cleanup(func() {
		telemetry.SetRecording(false)
		otel.SetTracerProvider(previous)
		_ = provider.Shutdown(context.Background())
	})

	db, err := New(t.TempDir() + "/trace.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	_, end := telemetry.Start(context.Background(), "root")
	func() {
		defer telemetry.Step("helper")()
		if _, err := db.Exec(`CREATE TABLE traced (id TEXT)`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO traced (id) VALUES (?)`, "secret-value"); err != nil {
			t.Fatal(err)
		}
		var id string
		if err := db.QueryRow(`SELECT id FROM traced WHERE id = ?`, "secret-value").Scan(&id); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`CREATE TABLE traced_lit (id TEXT DEFAULT 'secret-value')`); err != nil {
			t.Fatal(err)
		}
	}()
	end()

	spans := exp.GetSpans()
	byName := map[string]int{}
	var insertParent, helperID trace.SpanID
	var sawHelper bool
	for _, span := range spans {
		byName[span.Name]++
		if span.Name == "helper" {
			sawHelper = true
			helperID = span.SpanContext.SpanID()
		}
	}
	if !sawHelper {
		t.Fatalf("spans = %v", names(spans))
	}
	for _, span := range spans {
		for _, attr := range span.Attributes {
			if strings.Contains(attr.Value.AsString(), "secret-value") {
				t.Fatalf("attribute %s leaked the argument: %s", attr.Key, attr.Value.AsString())
			}
		}
		if span.Name == "db.insert" {
			insertParent = span.Parent.SpanID()
			var args int
			var statement string
			for _, attr := range span.Attributes {
				if string(attr.Key) == "db.arg_count" {
					args = int(attr.Value.AsInt64())
				}
				if string(attr.Key) == "db.statement" {
					statement = attr.Value.AsString()
				}
			}
			if args != 1 || statement != "INSERT INTO traced (id) VALUES (?)" {
				t.Fatalf("insert attrs args=%d statement=%q", args, statement)
			}
		}
	}
	if insertParent != helperID {
		t.Fatalf("db.insert parent = %s, helper = %s, names = %v", insertParent, helperID, names(spans))
	}
	if byName["db.select"] != 1 || byName["db.exec"] < 1 {
		t.Fatalf("counts = %v", byName)
	}
}

func names(spans []tracetest.SpanStub) []string {
	out := make([]string, len(spans))
	for i, span := range spans {
		out[i] = span.Name
	}
	return out
}
