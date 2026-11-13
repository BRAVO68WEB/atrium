package oauth

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/oidc"
	"github.com/bravo68web/atrium/internal/queue"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
)

func (h *Handler) HandleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleDeviceAuthorization")()
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Failed to parse request",
		})
		return
	}

	// Check for duplicate parameters
	if hasDuplicateParams(r) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Duplicate parameters are not allowed",
		})
		return
	}
	if credentialsInURI(r) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "Client credentials must not be in the request URI",
		})
		return
	}

	clientID, clientSecret, authErr := h.credentials(r)
	if authErr != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

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
		if gt == "urn:ietf:params:oauth:grant-type:device_code" {
			hasGrantType = true
			break
		}
	}
	if !hasGrantType {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unauthorized_client",
			"error_description": "Client not authorized for device_code grant",
		})
		return
	}

	scopes, err := service.AllowedScopes(r.Form.Get("scope"), client.Scopes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_scope",
			"error_description": err.Error(),
		})
		return
	}

	deviceCode, err := crypto.GenerateDeviceCode()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to generate device code",
		})
		return
	}

	userCode, err := crypto.GenerateUserCode()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to generate user code",
		})
		return
	}

	interval := 5
	expiresIn := int(h.cfg.Security.DeviceCodeLifetime.Seconds())

	dc := &models.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     scopes,
		Status:     "pending",
		ExpiresAt:  time.Now().Add(h.cfg.Security.DeviceCodeLifetime),
		Interval:   interval,
	}

	if err := h.deviceRepo.Save(dc); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to save device code",
		})
		return
	}

	issuer := h.cfg.Security.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", h.cfg.Server.Port)
	}

	queueReq := &queue.AuthRequest{
		ID:             deviceCode,
		Type:           queue.AuthRequestTypeDevice,
		ClientID:       clientID,
		UserCode:       userCode,
		BindingMessage: fmt.Sprintf("Enter code: %s", userCode),
		Status:         queue.StatusPending,
		Interval:       interval,
		CreatedAt:      time.Now(),
		ExpiresAt:      dc.ExpiresAt,
	}

	if err := h.q.Enqueue(queueReq); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":             "server_error",
			"error_description": "Failed to enqueue device code request",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          issuer + "/device",
		"verification_uri_complete": issuer + "/device?user_code=" + userCode,
		"expires_in":                expiresIn,
		"interval":                  interval,
	})
}

func (h *Handler) HandleDeviceToken(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleDeviceToken")()
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	deviceCode := r.Form.Get("device_code")
	if deviceCode == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "device_code is required")
		return
	}

	clientID, clientSecret, authErr := h.credentials(r)
	if authErr != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	dc, err := h.deviceRepo.GetByDeviceCode(deviceCode)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid device code")
		return
	}

	if time.Now().After(dc.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "Device code expired")
		return
	}

	client, ok := h.requireClient(r.Context(), w, dc.ClientID, "", http.StatusBadRequest)
	if !ok {
		return
	}

	if authenticateClient(client, clientID, clientSecret, true) != "" {
		writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed")
		return
	}

	switch dc.Status {
	case "pending":
		writeTokenError(w, http.StatusBadRequest, "authorization_pending", "User has not yet approved the request")
		return
	case "denied":
		writeTokenError(w, http.StatusBadRequest, "access_denied", "User denied the request")
		return
	case "expired":
		writeTokenError(w, http.StatusBadRequest, "expired_token", "Device code expired")
		return
	}

	if dc.Status != "approved" {
		writeTokenError(w, http.StatusBadRequest, "authorization_pending", "Request is still pending")
		return
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}
	tokenType := boundTokenType(client)

	userID := dc.UserID
	if userID == "" {
		queueReq, qerr := h.q.GetByID(deviceCode)
		if qerr == nil && queueReq.UserID != "" {
			userID = queueReq.UserID
		}
	}

	scopes, err := h.narrowScopes(userID, "", dc.Scopes)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to resolve scopes")
		return
	}
	dc.Scopes = scopes

	accessToken, err := h.issueAccessToken(r.Context(), dc.ClientID, userID, strings.Join(dc.Scopes, " "), tokenType)
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
		ClientID:  dc.ClientID,
		UserID:    userID,
		Scopes:    dc.Scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    dc.ClientID,
		UserID:      userID,
		Scopes:      dc.Scopes,
		ExpiresAt:   time.Now().Add(h.cfg.Security.RefreshTokenLifetime),
	}

	h.stampCert(r, accessTok)
	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.tokenRepo.SaveRefreshToken(refreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	if containsScope(dc.Scopes, "openid") && h.oidcHandler != nil {
		idToken, err := h.oidcHandler.CreateIDToken(r.Context(), dc.ClientID, userID, "", dc.Scopes, oidc.IDTokenExtra{SID: dc.SessionID, AuthTime: dc.AuthTime})
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to create ID token")
			return
		}
		writeOIDCTokenResponse(w, accessToken, refreshToken, idToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(dc.Scopes, " "))
		return
	}
	writeTokenResponse(w, accessToken, refreshToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(dc.Scopes, " "))
}

func (h *Handler) HandleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("oauth.Handler.HandleDeviceVerification")()
	if err := r.ParseForm(); err != nil && r.Method == http.MethodPost {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost && !service.CSRFMatch(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":             "csrf_failed",
			"error_description": "CSRF token is missing or invalid",
		})
		return
	}
	userCode := r.Form.Get("user_code")
	if userCode == "" {
		userCode = r.URL.Query().Get("user_code")
	}
	session := h.getSession(r)
	if session == nil || !session.Authenticated || session.PasswordPending || (h.cfg.Security.MFA.Required && !session.MFAVerified) {
		next := "/device"
		if userCode != "" {
			next = "/device?user_code=" + url.QueryEscape(userCode)
		}
		target := "/login?next=" + url.QueryEscape(next)
		if session != nil && h.cfg.Security.MFA.Required && !session.MFAVerified {
			target = "/login/mfa?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	if userCode == "" {
		msg := ""
		if r.Method == http.MethodPost {
			msg = "Enter the code shown on your device."
		}
		h.renderDevice(w, r, "", msg, "", nil)
		return
	}
	dc, err := h.deviceRepo.GetByUserCode(userCode)
	if err != nil || time.Now().After(dc.ExpiresAt) || dc.Status == "expired" {
		h.renderDevice(w, r, userCode, "That code is invalid or has expired.", "", nil)
		return
	}
	client, err := h.clientRepo.GetByID(dc.ClientID)
	if err != nil {
		h.renderDevice(w, r, userCode, "The application for this code is no longer registered.", "", nil)
		return
	}
	if r.Method == http.MethodGet || r.Form.Get("action") == "" {
		h.renderDevice(w, r, userCode, "", client.Name, dc.Scopes)
		return
	}
	if r.Form.Get("action") == "deny" {
		_ = h.deviceRepo.UpdateStatus(dc.DeviceCode, "denied")
		_ = h.q.Deny(dc.DeviceCode, "User denied the request")
		h.renderDeviceDone(w, false)
		return
	}
	if err := h.deviceRepo.Approve(dc.DeviceCode, session.UserID, session.ID, session.AuthTime); err != nil {
		h.renderDevice(w, r, userCode, "Could not approve the device.", client.Name, dc.Scopes)
		return
	}
	_ = h.q.Approve(dc.DeviceCode, session.UserID)
	if h.sessions != nil {
		_ = h.sessions.RecordClient(session.ID, dc.ClientID)
	}
	h.renderDeviceDone(w, true)
}

func (h *Handler) renderDevice(w http.ResponseWriter, r *http.Request, userCode, errMsg, clientName string, scopes []string) {
	defer telemetry.Step("oauth.Handler.renderDevice")()
	data := map[string]any{
		"Error":      errMsg,
		"UserCode":   userCode,
		"ClientName": clientName,
		"Scopes":     scopes,
		"Confirm":    clientName != "",
		"Done":       false,
		"Approved":   false,
		"CSRFToken":  service.IssueCSRF(w, r, h.cfg != nil && h.cfg.Server.TLS.Enabled),
	}
	h.brandTheme.Apply(data, "Device Authorization", "Device authorization", clientName)
	if h.pages != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.pages.ExecuteTemplate(w, "device.html", data); err == nil {
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body><h1>Device authorization</h1><p>%s</p>
<form method="POST" action="/device"><input type="hidden" name="csrf_token" value="%s"><input name="user_code" value="%s"><button name="action" value="approve">Approve</button><button name="action" value="deny">Deny</button></form></body></html>`,
		html.EscapeString(errMsg), html.EscapeString(data["CSRFToken"].(string)), html.EscapeString(userCode))
}

func (h *Handler) renderDeviceDone(w http.ResponseWriter, approved bool) {
	defer telemetry.Step("oauth.Handler.renderDeviceDone")()
	data := map[string]any{"Done": true, "Approved": approved, "Error": "", "Confirm": false}
	h.brandTheme.Apply(data, "Device Authorization", "Device authorization", "")
	if h.pages != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.pages.ExecuteTemplate(w, "device.html", data); err == nil {
			return
		}
	}
	msg := "Authorization approved. Return to your device."
	if !approved {
		msg = "Authorization denied."
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><body><h1>%s</h1></body></html>`, html.EscapeString(msg))
}
