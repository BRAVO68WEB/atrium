package dashboard

import (
	"net/http"
	"strings"
	"testing"
)

func TestClientSecretVisibility(t *testing.T) {
	listed := redact("/api/clients", http.MethodGet, []byte(`[{"id":"app","secret":"hide-me"}]`))
	if strings.Contains(string(listed), "hide-me") {
		t.Fatalf("list %s", listed)
	}
	one := redact("/api/clients/app", http.MethodGet, []byte(`{"id":"app","secret":"saved-secret"}`))
	if !strings.Contains(string(one), "saved-secret") {
		t.Fatalf("get %s", one)
	}
	reset := redact("/api/clients/app/secret", http.MethodPost, []byte(`{"secret":"new-secret"}`))
	if !strings.Contains(string(reset), "new-secret") {
		t.Fatalf("reset %s", reset)
	}
}
