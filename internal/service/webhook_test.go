package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/bravo68web/atrium/internal/background"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/testpg"
)

func TestWebhookFiltersAndSigns(t *testing.T) {
	db := testpg.Open(t)
	var mu sync.Mutex
	var gotEvent, gotBody string
	var sigOK bool
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-Webhook-Timestamp")
		mac := hmac.New(sha256.New, []byte("topsecret"))
		_, _ = mac.Write([]byte(ts + "." + string(body)))
		ok := r.Header.Get("X-Webhook-Signature") == "sha256="+hex.EncodeToString(mac.Sum(nil))
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		gotEvent = r.Header.Get("X-Webhook-Event")
		gotBody = string(body)
		sigOK = true
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()

	hooks := NewWebhookDispatcher(repository.NewWebhookRepository(db))
	if _, err := hooks.Create(WebhookInput{URL: receiver.URL, Secret: "topsecret", Events: []string{EventLogin}}); err != nil {
		t.Fatal(err)
	}
	if _, err := hooks.Create(WebhookInput{URL: "ftp://example.com/hook", Events: []string{EventLogin}}); err == nil {
		t.Fatal("expected invalid url")
	}
	if _, err := hooks.Create(WebhookInput{URL: receiver.URL, Events: []string{"nope"}}); err == nil {
		t.Fatal("expected unknown event")
	}

	hooks.Emit(EventLogout, map[string]any{"user_id": "u"})
	background.Wait()
	mu.Lock()
	if gotEvent != "" {
		t.Fatalf("logout was delivered to a login subscription: %s", gotEvent)
	}
	mu.Unlock()

	hooks.Emit(EventLogin, map[string]any{"user_id": "u", "username": "ada"})
	background.Wait()
	mu.Lock()
	defer mu.Unlock()
	if gotEvent != EventLogin || !sigOK {
		t.Fatalf("event %q signed %v body %s", gotEvent, sigOK, gotBody)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(gotBody), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["event"] != EventLogin {
		t.Fatalf("payload %#v", payload)
	}
}
