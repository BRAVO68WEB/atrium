package push_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/bravo68web/atrium/internal/service"
	"github.com/go-jose/go-jose/v4"
)

type wakeInbox struct {
	mu     sync.Mutex
	bodies [][]byte
	status int
}

func newWakeInbox(t *testing.T, status int) (*httptest.Server, *wakeInbox) {
	t.Helper()
	box := &wakeInbox{status: status}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type %s", r.Header.Get("Content-Type"))
		}
		box.mu.Lock()
		box.bodies = append(box.bodies, body)
		box.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(server.Close)
	return server, box
}

func (b *wakeInbox) all() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([][]byte, len(b.bodies))
	copy(out, b.bodies)
	return out
}

func TestPingPostsAnOpaqueWake(t *testing.T) {
	hit, box := newWakeInbox(t, http.StatusNoContent)
	cfg := pushTestConfig()
	cfg.Push.PingEnabled = true
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1"}
	ts := newServer(t, cfg)
	token := managementToken(t, ts.URL)
	createUser(t, ts.URL, token)
	browser := signIn(t, ts.URL)
	dpop := service.NewDPoPService()
	key, _ := dpop.GenerateKeyPair()
	registered := registerPayload(t, ts.URL, enroll(t, browser, ts.URL).Token, dpop.ExportPublicKeyAsJWK(&key.PublicKey), map[string]any{
		"push_address": hit.URL + "/wake",
	})
	if registered.Status != http.StatusCreated {
		t.Fatalf("register %d %s", registered.Status, registered.Body)
	}
	client := createPushClient(t, ts.URL, token)
	authReqID := pushCIBAInteractionOK(t, ts.URL, client, "ada", "", "42")
	bodies := box.all()
	if len(bodies) != 1 {
		t.Fatalf("wakes %d", len(bodies))
	}
	var wake map[string]any
	if err := json.Unmarshal(bodies[0], &wake); err != nil {
		t.Fatal(err)
	}
	if len(wake) != 2 || wake["wake_reason"] != "auth_request" || wake["ref_id"] != authReqID {
		t.Fatalf("wake %s", bodies[0])
	}

	revoked := revokeDevice(t, ts.URL, dpop, key, deviceID(t, registered.Body), credential(t, registered.Body), "")
	if revoked.Status != http.StatusNoContent {
		t.Fatalf("revoke %d %s", revoked.Status, revoked.Body)
	}
	bodies = box.all()
	if len(bodies) != 2 {
		t.Fatalf("revoke wakes %d", len(bodies))
	}
	_ = json.Unmarshal(bodies[1], &wake)
	if len(wake) != 2 || wake["wake_reason"] != "device_revoked" || wake["ref_id"] != deviceID(t, registered.Body) {
		t.Fatalf("revoke wake %s", bodies[1])
	}
}

func TestAFailedWakeStillAuthorizes(t *testing.T) {
	cfg := pushTestConfig()
	cfg.Push.PingEnabled = true
	ts := newServer(t, cfg)
	token := managementToken(t, ts.URL)
	createUser(t, ts.URL, token)
	browser := signIn(t, ts.URL)
	dpop := service.NewDPoPService()
	key, _ := dpop.GenerateKeyPair()
	registered := registerPayload(t, ts.URL, enroll(t, browser, ts.URL).Token, dpop.ExportPublicKeyAsJWK(&key.PublicKey), map[string]any{
		"push_address": "https://127.0.0.1:9/wake",
	})
	if registered.Status != http.StatusCreated {
		t.Fatalf("register %d %s", registered.Status, registered.Body)
	}
	client := createPushClient(t, ts.URL, token)
	authReqID := pushCIBAInteractionOK(t, ts.URL, client, "ada", "", "42")
	if authReqID == "" {
		t.Fatal("missing auth req")
	}
}

func TestPushUsesTheRelayThenPing(t *testing.T) {
	relay, relayBox := newWakeInbox(t, http.StatusNoContent)
	device, deviceBox := newWakeInbox(t, http.StatusNoContent)
	cfg := pushTestConfig()
	cfg.Push.PushEnabled = true
	cfg.Push.PingEnabled = true
	cfg.Push.RelayEndpoint = relay.URL + "/relay"
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1"}
	ts := newServer(t, cfg)
	doc := getJSON(t, ts.URL+"/.well-known/oauth-push-notification")
	modes, _ := doc["delivery_modes_supported"].([]any)
	if len(modes) != 3 || modes[0] != "push" || modes[1] != "ping" || modes[2] != "poll" {
		t.Fatalf("modes %v", doc["delivery_modes_supported"])
	}
	if doc["push_relay_endpoint"] != cfg.Push.RelayEndpoint {
		t.Fatalf("relay %v", doc["push_relay_endpoint"])
	}
	token := managementToken(t, ts.URL)
	createUser(t, ts.URL, token)
	browser := signIn(t, ts.URL)
	dpop := service.NewDPoPService()
	key, _ := dpop.GenerateKeyPair()
	registered := registerPayload(t, ts.URL, enroll(t, browser, ts.URL).Token, dpop.ExportPublicKeyAsJWK(&key.PublicKey), map[string]any{
		"push_address": device.URL + "/wake",
	})
	if registered.Status != http.StatusCreated {
		t.Fatalf("register %d %s", registered.Status, registered.Body)
	}
	client := createPushClient(t, ts.URL, token)
	authReqID := pushCIBAInteractionOK(t, ts.URL, client, "ada", "", "42")
	if len(deviceBox.all()) != 0 || len(relayBox.all()) != 1 {
		t.Fatalf("device %d relay %d", len(deviceBox.all()), len(relayBox.all()))
	}
	var wake map[string]any
	_ = json.Unmarshal(relayBox.all()[0], &wake)
	if wake["wake_reason"] != "auth_request" || wake["ref_id"] != authReqID || wake["push_address"] != device.URL+"/wake" {
		t.Fatalf("relay body %s", relayBox.all()[0])
	}

	down, _ := newWakeInbox(t, http.StatusBadGateway)
	direct, directBox := newWakeInbox(t, http.StatusNoContent)
	cfg.Push.RelayEndpoint = down.URL + "/relay"
	second := newServer(t, cfg)
	token = managementToken(t, second.URL)
	createUser(t, second.URL, token)
	browser = signIn(t, second.URL)
	registered = registerPayload(t, second.URL, enroll(t, browser, second.URL).Token, dpop.ExportPublicKeyAsJWK(&key.PublicKey), map[string]any{
		"push_address": direct.URL + "/wake",
	})
	if registered.Status != http.StatusCreated {
		t.Fatalf("second register %d %s", registered.Status, registered.Body)
	}
	client = createPushClient(t, second.URL, token)
	_ = pushCIBAInteractionOK(t, second.URL, client, "ada", "", "42")
	if len(directBox.all()) != 1 {
		t.Fatalf("fallback %d", len(directBox.all()))
	}
	fallback := map[string]any{}
	_ = json.Unmarshal(directBox.all()[0], &fallback)
	if len(fallback) != 2 || fallback["wake_reason"] != "auth_request" {
		t.Fatalf("fallback body %s", directBox.all()[0])
	}
}

func TestPushSealsThePendingPull(t *testing.T) {
	hit, box := newWakeInbox(t, http.StatusNoContent)
	cfg := pushTestConfig()
	cfg.Push.PushEnabled = true
	cfg.Security.AllowInsecureFetch = true
	cfg.Security.FetchAllowIPs = []string{"127.0.0.1"}
	ts := newServer(t, cfg)
	doc := getJSON(t, ts.URL+"/.well-known/oauth-push-notification")
	modes, _ := doc["delivery_modes_supported"].([]any)
	if len(modes) != 2 || modes[0] != "push" || modes[1] != "poll" {
		t.Fatalf("modes %v", modes)
	}
	if _, ok := doc["push_relay_endpoint"]; ok {
		t.Fatalf("relay advertised %v", doc["push_relay_endpoint"])
	}
	token := managementToken(t, ts.URL)
	createUser(t, ts.URL, token)
	browser := signIn(t, ts.URL)
	dpop := service.NewDPoPService()
	key, _ := dpop.GenerateKeyPair()
	registered := registerPayload(t, ts.URL, enroll(t, browser, ts.URL).Token, dpop.ExportPublicKeyAsJWK(&key.PublicKey), map[string]any{
		"push_address": hit.URL + "/wake",
	})
	if registered.Status != http.StatusCreated {
		t.Fatalf("register %d %s", registered.Status, registered.Body)
	}
	client := createPushClient(t, ts.URL, token)
	authReqID := pushCIBAInteractionOK(t, ts.URL, client, "ada", "boolean", "42")
	if len(box.all()) != 1 {
		t.Fatalf("wakes %d", len(box.all()))
	}
	var wake map[string]any
	_ = json.Unmarshal(box.all()[0], &wake)
	if len(wake) != 2 || wake["ref_id"] != authReqID {
		t.Fatalf("wake %s", box.all()[0])
	}
	id := deviceID(t, registered.Body)
	cred := credential(t, registered.Body)
	sealed := pollAccept(t, ts.URL, dpop, key, id, cred, "", "application/jose")
	if sealed.Status != http.StatusOK || !strings.Contains(sealed.Header.Get("Content-Type"), "application/jose") {
		t.Fatalf("jose %d %s %s", sealed.Status, sealed.Header.Get("Content-Type"), sealed.Body)
	}
	object, err := jose.ParseEncrypted(sealed.Body, []jose.KeyAlgorithm{jose.ECDH_ES_A256KW}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	plain, err := object.Decrypt(key)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), authReqID) {
		t.Fatalf("plain %s", plain)
	}
	open := pollAccept(t, ts.URL, dpop, key, id, cred, sealed.Header.Get("Replay-Nonce"), "")
	if open.Status != http.StatusOK || !strings.Contains(open.Header.Get("Content-Type"), "application/json") || !strings.Contains(open.Body, authReqID) {
		t.Fatalf("json %d %s %s", open.Status, open.Header.Get("Content-Type"), open.Body)
	}

	var logs strings.Builder
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	decided := postDelivery(t, ts.URL, dpop, key, id, cred, authReqID, open.Header.Get("Replay-Nonce"), "poll")
	if decided.Status != http.StatusNoContent || !strings.Contains(logs.String(), "fell back to poll") {
		t.Fatalf("decide %d %s log %s", decided.Status, decided.Body, logs.String())
	}
}

func TestDeliveryModeMustBeKnown(t *testing.T) {
	cfg := pushTestConfig()
	ts := newServer(t, cfg)
	res := postJSON(t, ts.URL+"/push/pending", `{"delivery_mode":"sms"}`, "")
	if res.Status != http.StatusBadRequest || !strings.Contains(res.Body, "delivery_mode") {
		t.Fatalf("mode %d %s", res.Status, res.Body)
	}
}

func deviceID(t *testing.T, body string) string {
	t.Helper()
	var doc map[string]any
	_ = json.Unmarshal([]byte(body), &doc)
	return str(doc["device_id"])
}

func credential(t *testing.T, body string) string {
	t.Helper()
	var doc map[string]any
	_ = json.Unmarshal([]byte(body), &doc)
	return str(doc["device_credential"])
}

func pollAccept(t *testing.T, base string, dpop *service.DPoPService, key *ecdsa.PrivateKey, id, credential, nonce, accept string) httpResult {
	t.Helper()
	rawURL := base + "/push/pending?device_id=" + url.QueryEscape(id)
	proof, err := dpop.CreateDPoPProof(key, http.MethodGet, rawURL, "")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("DPoP", proof)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if nonce != "" {
		req.Header.Set("Replay-Nonce", nonce)
	}
	return do(t, req)
}

func postDelivery(t *testing.T, base string, dpop *service.DPoPService, key *ecdsa.PrivateKey, id, credential, authReqID, nonce, mode string) httpResult {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{
		"device_id":     id,
		"auth_req_id":   authReqID,
		"action":        "approve",
		"delivery_mode": mode,
	})
	proof, err := dpop.CreateDPoPProof(key, http.MethodPost, base+"/push/pending", "")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, base+"/push/pending", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("DPoP", proof)
	req.Header.Set("Replay-Nonce", nonce)
	return do(t, req)
}
