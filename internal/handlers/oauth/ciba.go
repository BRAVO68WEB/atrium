package oauth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"errors"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/push"
	"github.com/bravo68web/oauth-impl/internal/queue"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

func (h *Handler) HandleBCAuthorize(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Failed to parse request",
		})
		return
	}

	clientID, clientSecret := presentedClient(r)

	if clientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "client_id is required",
		})
		return
	}

	client, err := h.clientRepo.GetByID(clientID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_client",
			"error_description": "Client not found",
		})
		return
	}

	if authenticateClient(client, clientID, clientSecret, false) != "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	hasGrantType := false
	for _, gt := range client.GrantTypes {
		if gt == "urn:openid:params:grant-type:ciba" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unauthorized_client",
			"error_description": "Client not authorized for CIBA",
		})
		return
	}

	loginHint := r.Form.Get("login_hint")
	if loginHint == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "login_hint is required",
		})
		return
	}

	scope := r.Form.Get("scope")
	if scope == "" {
		scope = "openid"
	}
	scopes := crypto.NormalizeScopes(scope)

	bindingMessage := r.Form.Get("binding_message")
	interaction := r.Form.Get("interaction_type")

	authReqID, err := crypto.GenerateToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to generate auth_req_id",
		})
		return
	}

	interval := 5
	expiresIn := 600 // Default 10 minutes

	resolvedUserID := ""
	if h.userSvc != nil {
		if user, err := h.userSvc.FindByLogin(loginHint); err == nil && user != nil {
			resolvedUserID = user.ID
		}
	}
	if h.deviceLogin != nil && resolvedUserID != "" {
		chosen, message, prepErr := h.deviceLogin.PrepareLogin(resolvedUserID, authReqID, interaction, bindingMessage)
		if errors.Is(prepErr, push.ErrDeviceRevoked) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "device_revoked",
				"error_description": "the authenticator device was revoked",
			})
			return
		}
		if errors.Is(prepErr, push.ErrWeakInteraction) {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "interaction_type is below the minimum",
			})
			return
		}
		if prepErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":             "server_error",
				"error_description": "Failed to bind the authenticator",
			})
			return
		}
		if chosen != "" {
			bindingMessage = message
		}
	}
	cibaReq := &models.CIBARequest{
		AuthReqID:      authReqID,
		ClientID:       clientID,
		UserID:         resolvedUserID,
		BindingMessage: bindingMessage,
		Scopes:         scopes,
		Status:         "pending",
		DeliveryMode:   "poll",
		ExpiresAt:      time.Now().Add(time.Duration(expiresIn) * time.Second),
		Interval:       interval,
	}

	if err := h.cibaRepo.Save(cibaReq); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to save CIBA request",
		})
		return
	}

	queueReq := &queue.AuthRequest{
		ID:             authReqID,
		Type:           queue.AuthRequestTypeCIBA,
		ClientID:       clientID,
		UserID:         loginHint,
		BindingMessage: bindingMessage,
		Status:         queue.StatusPending,
		Interval:       interval,
		CreatedAt:      time.Now(),
		ExpiresAt:      cibaReq.ExpiresAt,
	}

	if err := h.q.Enqueue(queueReq); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to enqueue CIBA request",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"auth_req_id": authReqID,
		"expires_in":  expiresIn,
		"interval":    interval,
	})
}

func (h *Handler) HandleCIBAToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	authReqID := r.Form.Get("auth_req_id")
	if authReqID == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "auth_req_id is required")
		return
	}

	clientID, clientSecret := presentedClient(r)

	cibaReq, err := h.cibaRepo.GetByID(authReqID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid auth_req_id")
		return
	}

	if time.Now().After(cibaReq.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "Auth request expired")
		return
	}

	client, ok := h.requireClient(w, cibaReq.ClientID, "", http.StatusBadRequest)
	if !ok {
		return
	}

	if authenticateClient(client, clientID, clientSecret, true) != "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}

	if h.deviceLogin != nil && h.deviceLogin.DeviceRevoked(authReqID) {
		writeTokenError(w, http.StatusBadRequest, "device_revoked", "the authenticator device was revoked")
		return
	}

	switch cibaReq.Status {
	case "pending":
		writeTokenError(w, http.StatusBadRequest, "authorization_pending", "User has not yet approved the request")
		return
	case "denied":
		writeTokenError(w, http.StatusBadRequest, "access_denied", "User denied the request")
		return
	case "expired":
		writeTokenError(w, http.StatusBadRequest, "expired_token", "Auth request expired")
		return
	}

	if cibaReq.Status != "approved" {
		writeTokenError(w, http.StatusBadRequest, "authorization_pending", "Request is still pending")
		return
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	tokenType := boundTokenType(client)

	var userID string
	if queueReq, qerr := h.q.GetByID(authReqID); qerr == nil && queueReq.UserID != "" {
		userID = queueReq.UserID
	}

	accessToken, err := h.issueAccessToken(cibaReq.ClientID, userID, strings.Join(cibaReq.Scopes, " "), tokenType)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	refreshToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  cibaReq.ClientID,
		UserID:    userID,
		Scopes:    cibaReq.Scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(3600 * time.Second),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    cibaReq.ClientID,
		UserID:      userID,
		Scopes:      cibaReq.Scopes,
		ExpiresAt:   time.Now().Add(86400 * time.Second),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.tokenRepo.SaveRefreshToken(refreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	writeTokenResponse(w, accessToken, refreshToken, 3600, tokenType, strings.Join(cibaReq.Scopes, " "))
}

func (h *Handler) HandleCIBAStatus(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_req_id")
	if authReqID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
		return
	}

	cibaReq, err := h.cibaRepo.GetByID(authReqID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "not_found",
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"auth_req_id": cibaReq.AuthReqID,
		"status":      cibaReq.Status,
		"expires_at":  cibaReq.ExpiresAt.Unix(),
	})
}

func (h *Handler) HandleCIBAListPending(w http.ResponseWriter, r *http.Request) {
	_ = r
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"pending_requests": []interface{}{},
	})
}

// CompleteCIBA records the device owner's decision for a pending request.
func (h *Handler) CompleteCIBA(authReqID, userID string, approve bool) error {
	if _, err := h.cibaRepo.GetByID(authReqID); err != nil {
		return err
	}
	if approve {
		if err := h.cibaRepo.UpdateStatus(authReqID, "approved"); err != nil {
			return err
		}
		return h.q.Approve(authReqID, userID)
	}
	if err := h.cibaRepo.UpdateStatus(authReqID, "denied"); err != nil {
		return err
	}
	return h.q.Deny(authReqID, "User denied the request")
}

func (h *Handler) HandleCIBAApprove(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_req_id")
	userID := r.URL.Query().Get("user_id")

	if authReqID == "" || userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
		return
	}

	cibaReq, err := h.cibaRepo.GetByID(authReqID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "not_found",
		})
		return
	}

	if err := h.cibaRepo.UpdateStatus(authReqID, "approved"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		})
		return
	}

	_ = h.q.Approve(authReqID, userID)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"auth_req_id":     authReqID,
		"status":          "approved",
		"client_id":       cibaReq.ClientID,
		"binding_message": cibaReq.BindingMessage,
		"expires_at":      cibaReq.ExpiresAt.Unix(),
	})
}

func (h *Handler) HandleCIBADeny(w http.ResponseWriter, r *http.Request) {
	authReqID := r.URL.Query().Get("auth_req_id")
	reason := r.URL.Query().Get("reason")

	if authReqID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid_request",
		})
		return
	}

	cibaReq, err := h.cibaRepo.GetByID(authReqID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "not_found",
		})
		return
	}

	if err := h.cibaRepo.UpdateStatus(authReqID, "denied"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "server_error",
		})
		return
	}

	if reason == "" {
		reason = "User denied the request"
	}
	_ = h.q.Deny(authReqID, reason)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"auth_req_id":     authReqID,
		"status":          "denied",
		"client_id":       cibaReq.ClientID,
		"binding_message": cibaReq.BindingMessage,
	})
}
