package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestManagementClientIsNotEditable(t *testing.T) {
	mgmt := NewManagementController(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	mgmt.SetManagementClientID(" key ")
	mux := chi.NewRouter()
	mux.Post("/api/clients", mgmt.HandleCreateClient)
	mux.Put("/api/clients/{clientID}", mgmt.HandleUpdateClient)
	mux.Delete("/api/clients/{clientID}", mgmt.HandleDeleteClient)

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPut, "/api/clients/key", `{"name":"renamed"}`},
		{http.MethodDelete, "/api/clients/key", ``},
		{http.MethodPost, "/api/clients", `{"id":"key","name":"other"}`},
	}
	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s %s = %d %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "not editable") {
			t.Fatalf("%s %s body %s", tc.method, tc.path, rec.Body.String())
		}
	}
}
