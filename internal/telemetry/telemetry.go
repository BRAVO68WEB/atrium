// Package telemetry emits OpenTelemetry spans for the authorization server.
// Tracing is a no-op until telemetry.enabled is set and an OTLP endpoint is configured.
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	applog "github.com/bravo68web/oauth-impl/internal/log"
	"github.com/felixge/httpsnoop"
	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "github.com/bravo68web/oauth-impl"

// Setup installs a global tracer provider. A disabled config leaves the
// default no-op provider in place and the returned shutdown function does nothing.
func Setup(ctx context.Context, cfg *config.TelemetryConfig) (func(context.Context) error, error) {
	noop := func(context.Context) error { return nil }
	if cfg == nil || !cfg.Enabled {
		return noop, nil
	}
	opts := []otlptracehttp.Option{}
	endpoint := strings.TrimSpace(cfg.OTLPEndpoint)
	if strings.Contains(endpoint, "://") {
		opts = append(opts, otlptracehttp.WithEndpointURL(endpoint))
	} else {
		opts = append(opts, otlptracehttp.WithEndpoint(endpoint))
	}
	if cfg.Insecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	name := cfg.ServiceName
	if name == "" {
		name = "oauth-server"
	}
	ratio := cfg.SampleRatio
	if ratio <= 0 {
		ratio = 1
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))),
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", name))),
	)
	otel.SetTracerProvider(provider)
	SetRecording(true)
	return provider.Shutdown, nil
}

// Middleware starts a span for each request and, when that span is recording,
// logs the trace and span ids after the handler returns.
func Middleware(next http.Handler) http.Handler {
	named := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		span := trace.SpanFromContext(r.Context())
		var release func()
		if span.IsRecording() {
			release = Bind(r.Context())
		}
		var snippet bytes.Buffer
		status := http.StatusOK
		sawHeader := false
		wrapped := httpsnoop.Wrap(w, httpsnoop.Hooks{
			WriteHeader: func(nextHeader httpsnoop.WriteHeaderFunc) httpsnoop.WriteHeaderFunc {
				return func(code int) {
					if !sawHeader {
						status = code
						sawHeader = true
					}
					nextHeader(code)
				}
			},
			Write: func(nextWrite httpsnoop.WriteFunc) httpsnoop.WriteFunc {
				return func(p []byte) (int, error) {
					if !sawHeader {
						status = http.StatusOK
						sawHeader = true
					}
					rememberPrefix(&snippet, p)
					return nextWrite(p)
				}
			},
		})
		next.ServeHTTP(wrapped, r)
		if release != nil {
			release()
		}
		route := r.URL.Path
		if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
			route = rc.RoutePattern()
			span.SetName(route)
		}
		client := clientID(r)
		grant := ""
		if r.Form != nil {
			grant = r.Form.Get("grant_type")
		}
		org := r.URL.Query().Get("organization")
		if org == "" && r.Form != nil {
			org = r.Form.Get("organization")
		}
		code := oauthError(snippet.Bytes())
		if span.IsRecording() {
			attrs := make([]attribute.KeyValue, 0, 4)
			if client != "" {
				attrs = append(attrs, attribute.String("client_id", client))
			}
			if grant != "" {
				attrs = append(attrs, attribute.String("grant_type", grant))
			}
			if org != "" {
				attrs = append(attrs, attribute.String("org_id", org))
			}
			if code != "" {
				attrs = append(attrs, attribute.String("oauth.error", code))
			}
			span.SetAttributes(attrs...)
			if status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(status))
			}
		}
		traceID, spanID := "", ""
		if span.IsRecording() {
			sc := span.SpanContext()
			traceID = sc.TraceID().String()
			spanID = sc.SpanID().String()
		}
		applog.Info("request",
			"method", r.Method,
			"route", route,
			"status", status,
			"duration_ms", time.Since(started).Milliseconds(),
			"client_id", client,
			"grant_type", grant,
			"org_id", org,
			"oauth.error", code,
			"trace_id", traceID,
			"span_id", spanID,
		)
	})
	return otelhttp.NewMiddleware("http.request",
		otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
			return spanName(r.URL.Path)
		}),
	)(named)
}

func spanName(path string) string {
	switch path {
	case "/oauth/authorize":
		return "oauth.authorize"
	case "/oauth/token":
		return "oauth.token"
	case "/oauth/introspect":
		return "oauth.introspect"
	case "/oauth/revoke":
		return "oauth.revoke"
	case "/oidc/userinfo":
		return "oidc.userinfo"
	case "/login":
		return "login"
	default:
		if strings.HasPrefix(path, "/login/") {
			return "login"
		}
		return "http.request"
	}
}

func clientID(r *http.Request) string {
	if id, _, ok := r.BasicAuth(); ok && id != "" {
		return id
	}
	if r.Form != nil {
		return r.Form.Get("client_id")
	}
	return r.URL.Query().Get("client_id")
}

func oauthError(body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return ""
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	if len(payload.Error) > 64 || strings.ContainsAny(payload.Error, " \n\r") {
		return ""
	}
	return payload.Error
}

func rememberPrefix(dst *bytes.Buffer, p []byte) {
	if dst.Len() >= 512 {
		return
	}
	remain := 512 - dst.Len()
	if len(p) > remain {
		p = p[:remain]
	}
	_, _ = dst.Write(p)
}

// Tracer is the process tracer. Tests and handlers use it when they need a child span.
func Tracer() trace.Tracer {
	return otel.Tracer(tracerName)
}

// ShutdownTimeout bounds provider flush during process exit.
const ShutdownTimeout = 5 * time.Second
