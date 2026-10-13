package push

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/golang-jwt/jwt/v5"
)

// Handler is the HTTP surface for push-device registration.
type Handler struct {
	svc     *Service
	clients *repository.ClientRepository
	sign    func(jwt.MapClaims) (string, error)
	keyfunc jwt.Keyfunc
	session func(r *http.Request) (userID string, ok bool)
}

func NewHandler(svc *Service, clients *repository.ClientRepository, sign func(jwt.MapClaims) (string, error), keyfunc jwt.Keyfunc, session func(*http.Request) (string, bool)) *Handler {
	return &Handler{svc: svc, clients: clients, sign: sign, keyfunc: keyfunc, session: session}
}

func (h *Handler) Service() *Service { return h.svc }

func (h *Handler) Discovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(h.svc.Discovery())
}

func (h *Handler) Enroll(w http.ResponseWriter, r *http.Request) (Enrollment, bool) {
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

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
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

func (h *Handler) Rotate(w http.ResponseWriter, r *http.Request) {
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
	header := r.Header.Get("Authorization")
	if len(header) > 7 && strings.EqualFold(header[:7], "bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return r.Form.Get("token")
}

func writeErr(w http.ResponseWriter, err error) {
	if item, ok := err.(Problem); ok {
		writeProblem(w, item)
		return
	}
	writeProblem(w, problem(http.StatusInternalServerError, "server_error", "request failed"))
}

func writeProblem(w http.ResponseWriter, item Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	if item.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	w.WriteHeader(item.Status)
	_ = json.NewEncoder(w).Encode(item)
}
