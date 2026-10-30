package dashboard

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/telemetry"
)

func (h *Handler) proxy(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("dashboard.proxy")()
	item, ok := sessionFrom(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "invalid_token", "Sign in to the dashboard")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	path := "/api" + strings.TrimPrefix(r.URL.Path, "/dashboard/api")
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, nil)
	req, err := http.NewRequestWithContext(ctx, r.Method, path, bytes.NewReader(body))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "server_error", "Failed to build request")
		return
	}
	req.URL.Path = path
	req.URL.RawQuery = r.URL.RawQuery
	req.Host = r.Host
	req.Header = r.Header.Clone()
	req.Header.Del("Cookie")
	req.Header.Set("Authorization", "Bearer "+item.Token)
	req.ContentLength = int64(len(body))
	rec := newRecorder()
	h.api.ServeHTTP(rec, req)
	rec.flush(w, path, r.Method)
}
