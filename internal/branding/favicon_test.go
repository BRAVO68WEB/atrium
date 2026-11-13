package branding

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDefaultFavicon(t *testing.T) {
	rec := httptest.NewRecorder()
	ServeDefaultFavicon(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "image/png" {
		t.Fatalf("type %s", rec.Header().Get("Content-Type"))
	}
	if len(rec.Body.Bytes()) < 100 {
		t.Fatalf("favicon is %d bytes", rec.Body.Len())
	}
}
