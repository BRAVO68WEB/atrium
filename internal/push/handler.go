package push

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/golang-jwt/jwt/v5"
)

// Handler is the HTTP surface for push-device registration.
type Handler struct {
	svc      *Service
	clients  *repository.ClientRepository
	sign     func(jwt.MapClaims) (string, error)
	keyfunc  jwt.Keyfunc
	session  func(r *http.Request) (userID string, ok bool)
	complete func(authReqID, userID string, approve bool) error
}

func NewHandler(svc *Service, clients *repository.ClientRepository, sign func(jwt.MapClaims) (string, error), keyfunc jwt.Keyfunc, session func(*http.Request) (string, bool)) *Handler {
	defer telemetry.Step("push.NewHandler")()
	return &Handler{svc: svc, clients: clients, sign: sign, keyfunc: keyfunc, session: session}
}

func (h *Handler) Service() *Service {
	defer telemetry.Step(

		// SetComplete records the CIBA decision after the device poll succeeds.
		"push.Handler.Service")()
	return h.svc
}

func (h *Handler) SetComplete(fn func(authReqID, userID string, approve bool) error) {
	defer telemetry.Step("push.Handler.SetComplete")()
	if h != nil {
		h.complete = fn
	}
}

func (h *Handler) Discovery(w http.ResponseWriter, _ *http.Request) {
	defer telemetry.Step("push.Handler.Discovery")()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(h.svc.Discovery())
}

func (h *Handler) Enroll(w http.ResponseWriter, r *http.Request) (Enrollment, bool) {
	defer telemetry.Step("push.Handler.Enroll")()
	userID, ok := h.session(r)
	if !ok {
		return Enrollment{}, false
	}
	clientID := r.URL.Query().Get("client_id")
	if clientID != "" && h.clients != nil {
		if client, err := h.clients.GetByID(clientID); err != nil || client == nil {
			clientID = ""
		}
	}
	item, err := h.svc.IssueEnrollment(userID, clientID, h.sign)
	if err != nil {
		writeProblem(w, problem(http.StatusInternalServerError, "server_error", "enrollment token was not created"))
		return Enrollment{}, false
	}
	return item, true
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("push.Handler.Register")()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	registered, err := h.svc.Register(clientIP(r), body, h.keyfunc)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(registered)
}

func (h *Handler) Devices(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("push.Handler.Devices")()
	userID, ok := h.session(r)
	if !ok {
		writeProblem(w, problem(http.StatusUnauthorized, "login_required", "sign in to list devices"))
		return
	}
	list, err := h.svc.List(userID)
	if err != nil {
		writeProblem(w, problem(http.StatusInternalServerError, "server_error", "device list failed"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{"devices": list})
}

// Primary marks the signed-in user's chosen device.
func (h *Handler) Primary(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("push.Handler.Primary")()
	userID, ok := h.session(r)
	if !ok {
		writeProblem(w, problem(http.StatusUnauthorized, "login_required", "sign in to choose a device"))
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.DeviceID) == "" {
		writeProblem(w, problem(http.StatusBadRequest, "invalid_request", "device_id is required"))
		return
	}
	if err := h.svc.MakePrimary(userID, req.DeviceID); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EnrollUser issues a registration token for an admin recovery.
func (h *Handler) EnrollUser(userID string) (Enrollment, error) {
	defer telemetry.Step("push.Handler.EnrollUser")()
	if h == nil || h.svc == nil {
		return Enrollment{}, problem(http.StatusNotFound, "not_found", "push is disabled")
	}
	return h.svc.IssueEnrollment(userID, "", h.sign)
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("push.Handler.Revoke")()
	if err := r.ParseForm(); err != nil {
		writeProblem(w, problem(http.StatusBadRequest, "invalid_request", "form is invalid"))
		return
	}
	nonce, err := h.svc.Revoke(r, r.Form.Get("device_id"), bearerOrForm(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Pending(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("push.Handler.Pending")()
	deviceID := r.URL.Query().Get("device_id")
	list, nonce, err := h.svc.PollPending(r, deviceID, bearerOrForm(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	payload, err := json.Marshal(map[string]any{"pending": list})
	if err != nil {
		w.Header().Set("Replay-Nonce", nonce)
		writeErr(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Replay-Nonce", nonce)
	if wantsJose(r) {
		sealed, err := h.svc.SealPending(deviceID, payload)
		if err != nil {
			writeErr(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/jose")
		_, _ = w.Write([]byte(sealed))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(payload)
}

func wantsJose(r *http.Request) bool {
	defer telemetry.Step("push.wantsJose")()
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		media := strings.TrimSpace(strings.Split(part, ";")[0])
		if media == "application/jose" {
			return true
		}
	}
	return false
}

func (h *Handler) Decide(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("push.Handler.Decide")()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	var req struct {
		DeviceID     string `json:"device_id"`
		AuthReqID    string `json:"auth_req_id"`
		Action       string `json:"action"`
		Proof        string `json:"proof"`
		DeliveryMode string `json:"delivery_mode"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeProblem(w, problem(http.StatusBadRequest, "invalid_request", "decision body is invalid"))
		return
	}
	if req.DeliveryMode != "" && req.DeliveryMode != "push" && req.DeliveryMode != "poll" {
		writeProblem(w, problem(http.StatusBadRequest, "invalid_request", "delivery_mode must be push or poll"))
		return
	}
	userID, nonce, err := h.svc.PollDecide(r, req.DeviceID, bearerOrForm(r), req.AuthReqID, req.Action, req.Proof, req.DeliveryMode)
	if err != nil {
		if nonce != "" {
			w.Header().Set("Replay-Nonce", nonce)
		}
		writeErr(w, err)
		return
	}
	if h.complete != nil {
		if err := h.complete(req.AuthReqID, userID, req.Action != "deny"); err != nil {
			writeErr(w, err)
			return
		}
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Rotate(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("push.Handler.Rotate")()
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	registered, nonce, err := h.svc.Rotate(r, body, bearerOrForm(r))
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Replay-Nonce", nonce)
	_ = json.NewEncoder(w).Encode(registered)
}

func bearerOrForm(r *http.Request) string {
	defer telemetry.Step("push.bearerOrForm")()
	header := r.Header.Get("Authorization")
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return r.Form.Get("token")
}

func writeErr(w http.ResponseWriter, err error) {
	defer telemetry.Step("push.writeErr")()
	if item, ok := err.(Problem); ok {
		writeProblem(w, item)
		return
	}
	writeProblem(w, problem(http.StatusInternalServerError, "server_error", "request failed"))
}

func writeProblem(w http.ResponseWriter, item Problem) {
	defer telemetry.Step("push.writeProblem")()
	w.Header().Set("Content-Type", "application/problem+json")
	if item.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	w.WriteHeader(item.Status)
	_ = json.NewEncoder(w).Encode(item)
}
