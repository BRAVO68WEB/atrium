package controller

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/service"
)

type ManagementController struct {
	clientSvc    *service.ClientService
	userSvc      *service.UserService
	tokenSvc     *service.TokenService
	totpSvc      *service.TOTPService
	scopeRepo    *repository.ScopeRepository
	resourceRepo *repository.ResourceRepository
	consentRepo  *repository.ConsentRepository
	account      *service.AccountService
	sessions     *service.SessionService
	tokenRepo    *repository.TokenRepository
	hooks        *service.WebhookDispatcher
	audit        *service.AuditLog
	keys         *oidc.KeySet
	keyRetain    time.Duration
	orgs         *service.OrgService
	grants       *service.GrantService
}

func (c *ManagementController) SetGrants(g *service.GrantService) {
	if c != nil {
		c.grants = g
	}
}

func (c *ManagementController) SetAudit(a *service.AuditLog) {
	if c != nil {
		c.audit = a
	}
}

func (c *ManagementController) SetKeys(keys *oidc.KeySet, retain time.Duration) {
	if c != nil {
		c.keys = keys
		c.keyRetain = retain
	}
}

func (c *ManagementController) SetWebhooks(d *service.WebhookDispatcher) {
	c.hooks = d
}

func NewManagementController(
	clientSvc *service.ClientService,
	userSvc *service.UserService,
	tokenSvc *service.TokenService,
	totpSvc *service.TOTPService,
	scopeRepo *repository.ScopeRepository,
	resourceRepo *repository.ResourceRepository,
	consentRepo *repository.ConsentRepository,
	account *service.AccountService,
	sessions *service.SessionService,
	tokenRepo *repository.TokenRepository,
) *ManagementController {
	return &ManagementController{
		clientSvc:    clientSvc,
		userSvc:      userSvc,
		tokenSvc:     tokenSvc,
		totpSvc:      totpSvc,
		scopeRepo:    scopeRepo,
		resourceRepo: resourceRepo,
		consentRepo:  consentRepo,
		account:      account,
		sessions:     sessions,
		tokenRepo:    tokenRepo,
	}
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeProfileError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, service.ErrEmailRequired):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return true
	case errors.Is(err, service.ErrEmailTaken):
		writeError(w, http.StatusConflict, "already_exists", err.Error())
		return true
	default:
		return false
	}
}

func writeError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

// ─── Client Management ────────────────────────────────────

func (c *ManagementController) HandleListClients(w http.ResponseWriter, r *http.Request) {
	clients, err := c.clientSvc.ListClients()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list clients")
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (c *ManagementController) HandleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name                                       string   `json:"name"`
		RedirectURIs                               []string `json:"redirect_uris"`
		GrantTypes                                 []string `json:"grant_types"`
		Scopes                                     []string `json:"scopes"`
		TokenEndpointAuthMethod                    string   `json:"token_endpoint_auth_method"`
		DPoPBoundAccessTokens                      bool     `json:"dpop_bound_access_tokens"`
		RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests"`
		BackchannelTokenDeliveryMode               string   `json:"backchannel_token_delivery_mode"`
		BackchannelClientNotificationEndpoint      string   `json:"backchannel_client_notification_endpoint"`
		BackchannelAuthenticationRequestSigningAlg string   `json:"backchannel_authentication_request_signing_alg"`
		BackchannelLogoutURI                       string   `json:"backchannel_logout_uri"`
		BackchannelLogoutSessionRequired           *bool    `json:"backchannel_logout_session_required"`
		PostLogoutRedirectURIs                     []string `json:"post_logout_redirect_uris"`
		DCREnabled                                 bool     `json:"dcr_enabled"`
		CIMDEnabled                                bool     `json:"cimd_enabled"`
		SubjectType                                string   `json:"subject_type"`
		SectorIdentifierURI                        string   `json:"sector_identifier_uri"`
		JWKS                                       string   `json:"jwks"`
		IDTokenEncryptedResponseAlg                string   `json:"id_token_encrypted_response_alg"`
		IDTokenEncryptedResponseEnc                string   `json:"id_token_encrypted_response_enc"`
		UserinfoEncryptedResponseAlg               string   `json:"userinfo_encrypted_response_alg"`
		UserinfoEncryptedResponseEnc               string   `json:"userinfo_encrypted_response_enc"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	client, err := c.clientSvc.CreateClient(service.CreateClientInput{
		Name:                                  req.Name,
		RedirectURIs:                          req.RedirectURIs,
		GrantTypes:                            req.GrantTypes,
		Scopes:                                req.Scopes,
		TokenEndpointAuthMethod:               req.TokenEndpointAuthMethod,
		DPoPBoundAccessTokens:                 req.DPoPBoundAccessTokens,
		RequirePushedAuthorizationRequests:    req.RequirePushedAuthorizationRequests,
		BackchannelTokenDeliveryMode:          req.BackchannelTokenDeliveryMode,
		BackchannelClientNotificationEndpoint: req.BackchannelClientNotificationEndpoint,
		BackchannelAuthenticationRequestSigningAlg: req.BackchannelAuthenticationRequestSigningAlg,
		BackchannelLogoutURI:                       req.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:           req.BackchannelLogoutSessionRequired,
		PostLogoutRedirectURIs:                     req.PostLogoutRedirectURIs,
		DCREnabled:                                 req.DCREnabled,
		CIMDEnabled:                                req.CIMDEnabled,
		SubjectType:                                req.SubjectType,
		SectorIdentifierURI:                        req.SectorIdentifierURI,
		JWKS:                                       req.JWKS,
		IDTokenEncryptedResponseAlg:                req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:                req.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg:               req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc:               req.UserinfoEncryptedResponseEnc,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.writeAudit(r, "client.create", "client", client.ID, map[string]any{"name": client.Name})

	writeJSON(w, http.StatusCreated, client)
}

func (c *ManagementController) HandleGetClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	client, err := c.clientSvc.GetClient(clientID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Client not found")
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (c *ManagementController) HandleUpdateClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	existing, err := c.clientSvc.GetClient(clientID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Client not found")
		return
	}

	var req struct {
		Name                                       string   `json:"name"`
		RedirectURIs                               []string `json:"redirect_uris"`
		GrantTypes                                 []string `json:"grant_types"`
		Scopes                                     []string `json:"scopes"`
		TokenEndpointAuthMethod                    string   `json:"token_endpoint_auth_method"`
		DPoPBoundAccessTokens                      bool     `json:"dpop_bound_access_tokens"`
		RequirePushedAuthorizationRequests         bool     `json:"require_pushed_authorization_requests"`
		BackchannelTokenDeliveryMode               string   `json:"backchannel_token_delivery_mode"`
		BackchannelClientNotificationEndpoint      string   `json:"backchannel_client_notification_endpoint"`
		BackchannelAuthenticationRequestSigningAlg string   `json:"backchannel_authentication_request_signing_alg"`
		BackchannelLogoutURI                       string   `json:"backchannel_logout_uri"`
		BackchannelLogoutSessionRequired           *bool    `json:"backchannel_logout_session_required"`
		PostLogoutRedirectURIs                     []string `json:"post_logout_redirect_uris"`
		DCREnabled                                 *bool    `json:"dcr_enabled"`
		CIMDEnabled                                *bool    `json:"cimd_enabled"`
		SubjectType                                string   `json:"subject_type"`
		SectorIdentifierURI                        *string  `json:"sector_identifier_uri"`
		JWKS                                       *string  `json:"jwks"`
		IDTokenEncryptedResponseAlg                *string  `json:"id_token_encrypted_response_alg"`
		IDTokenEncryptedResponseEnc                *string  `json:"id_token_encrypted_response_enc"`
		UserinfoEncryptedResponseAlg               *string  `json:"userinfo_encrypted_response_alg"`
		UserinfoEncryptedResponseEnc               *string  `json:"userinfo_encrypted_response_enc"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.RedirectURIs != nil {
		existing.RedirectURIs = req.RedirectURIs
	}
	if req.GrantTypes != nil {
		existing.GrantTypes = req.GrantTypes
	}
	if req.Scopes != nil {
		existing.Scopes = req.Scopes
	}
	if req.TokenEndpointAuthMethod != "" {
		existing.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}
	existing.DPoPBoundAccessTokens = req.DPoPBoundAccessTokens
	existing.RequirePushedAuthorizationRequests = req.RequirePushedAuthorizationRequests
	existing.BackchannelTokenDeliveryMode = req.BackchannelTokenDeliveryMode
	existing.BackchannelClientNotificationEndpoint = req.BackchannelClientNotificationEndpoint
	existing.BackchannelAuthenticationRequestSigningAlg = req.BackchannelAuthenticationRequestSigningAlg
	existing.BackchannelLogoutURI = req.BackchannelLogoutURI
	if req.BackchannelLogoutSessionRequired != nil {
		existing.BackchannelLogoutSessionRequired = *req.BackchannelLogoutSessionRequired
	}
	if req.PostLogoutRedirectURIs != nil {
		existing.PostLogoutRedirectURIs = req.PostLogoutRedirectURIs
	}
	if req.DCREnabled != nil {
		existing.DCREnabled = *req.DCREnabled
	}
	if req.CIMDEnabled != nil {
		existing.CIMDEnabled = *req.CIMDEnabled
	}
	if req.SubjectType != "" {
		existing.SubjectType = req.SubjectType
	}
	if req.SectorIdentifierURI != nil {
		existing.SectorIdentifierURI = *req.SectorIdentifierURI
	}
	if req.JWKS != nil {
		existing.JWKS = *req.JWKS
	}
	if req.IDTokenEncryptedResponseAlg != nil {
		existing.IDTokenEncryptedResponseAlg = *req.IDTokenEncryptedResponseAlg
	}
	if req.IDTokenEncryptedResponseEnc != nil {
		existing.IDTokenEncryptedResponseEnc = *req.IDTokenEncryptedResponseEnc
	}
	if req.UserinfoEncryptedResponseAlg != nil {
		existing.UserinfoEncryptedResponseAlg = *req.UserinfoEncryptedResponseAlg
	}
	if req.UserinfoEncryptedResponseEnc != nil {
		existing.UserinfoEncryptedResponseEnc = *req.UserinfoEncryptedResponseEnc
	}

	if err := c.clientSvc.UpdateClient(existing); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.writeAudit(r, "client.update", "client", existing.ID, map[string]any{"name": existing.Name, "dcr_enabled": existing.DCREnabled, "cimd_enabled": existing.CIMDEnabled})

	writeJSON(w, http.StatusOK, existing)
}

func (c *ManagementController) HandleDeleteClient(w http.ResponseWriter, r *http.Request) {
	clientID := chi.URLParam(r, "clientID")
	if err := c.clientSvc.DeleteClient(clientID); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to delete client")
		return
	}
	c.writeAudit(r, "client.delete", "client", clientID, map[string]any{})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ─── User Management ──────────────────────────────────────

func (c *ManagementController) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := c.userSvc.ListUsers()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list users")
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (c *ManagementController) HandleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username      string            `json:"username"`
		Password      string            `json:"password"`
		Email         string            `json:"email"`
		Phone         string            `json:"phone_number"`
		GivenName     string            `json:"given_name"`
		FamilyName    string            `json:"family_name"`
		EmailVerified *bool             `json:"email_verified"`
		Disabled      bool              `json:"disabled"`
		Attributes    map[string]string `json:"attributes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	verified := req.Email != ""
	if req.EmailVerified != nil {
		verified = *req.EmailVerified
	}
	user, err := c.userSvc.InsertUser(service.NewUser{
		Username:      req.Username,
		Password:      req.Password,
		Email:         req.Email,
		Phone:         req.Phone,
		GivenName:     req.GivenName,
		FamilyName:    req.FamilyName,
		EmailVerified: verified,
		Disabled:      req.Disabled,
		Attributes:    req.Attributes,
	})
	if writePassword(w, err) {
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.writeAudit(r, "user.create", "user", user.ID, map[string]any{"username": user.Username})
	if c.account != nil {
		c.account.EmitRegistered(user, "management", "")
	}

	writeJSON(w, http.StatusCreated, user)
}

func (c *ManagementController) HandlePatchUser(w http.ResponseWriter, r *http.Request) {
	user, err := c.userSvc.GetUser(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	var req struct {
		userPatch
		Attributes map[string]string `json:"attributes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	wasDisabled := user.Disabled
	applyProfile(user, req.userPatch)
	if err := c.userSvc.UpdateProfile(user); err != nil {
		if writeProfileError(w, err) {
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to update user")
		return
	}
	if req.Attributes != nil {
		if err := c.userSvc.SetAttributes(user.ID, req.Attributes); err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", "Failed to update attributes")
			return
		}
		user.Attributes = req.Attributes
	}
	if req.Disabled != nil && *req.Disabled && !wasDisabled && c.account != nil {
		_ = c.account.SetDisabled(user, true)
		c.writeAudit(r, "user.disable", "user", user.ID, map[string]any{"username": user.Username})
	}
	writeJSON(w, http.StatusOK, user)
}

func (c *ManagementController) HandleSetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	userID := chi.URLParam(r, "userID")
	if err := c.account.AdminSetPassword(userID, req.Password); err != nil {
		if writePassword(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.writeAudit(r, "password.set", "user", userID, map[string]any{})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (c *ManagementController) HandleListUserSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := c.sessions.List(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list sessions")
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

func (c *ManagementController) HandleRevokeUserSession(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	sid := chi.URLParam(r, "sid")
	if err := c.account.RevokeSession(userID, sid); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Session not found")
		return
	}
	c.writeAudit(r, "session.revoke", "session", sid, map[string]any{"user_id": userID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (c *ManagementController) HandleUserLoginAnalytics(w http.ResponseWriter, r *http.Request) {
	window, err := loginWindow(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	report, err := c.account.LoginAnalytics(chi.URLParam(r, "userID"), window)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to build login analytics")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (c *ManagementController) HandleGlobalLoginAnalytics(w http.ResponseWriter, r *http.Request) {
	window, err := loginWindow(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	report, err := c.account.LoginAnalytics("", window)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to build login analytics")
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (c *ManagementController) HandleUserActivity(w http.ResponseWriter, r *http.Request) {
	events, err := c.account.Activity(chi.URLParam(r, "userID"), 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list activity")
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (c *ManagementController) HandleListRefreshTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := c.tokenRepo.ListRefreshTokens(r.URL.Query().Get("client_id"), r.URL.Query().Get("user_id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list refresh tokens")
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (c *ManagementController) HandleRevokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	rt, err := c.tokenRepo.GetRefreshByID(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Refresh token not found")
		return
	}
	_ = c.tokenRepo.RevokeRefreshToken(rt.Token)
	if rt.AccessToken != "" {
		_ = c.tokenRepo.RevokeAccessToken(rt.AccessToken)
	}
	c.writeAudit(r, "token.revoke", "refresh_token", rt.ID, map[string]any{"client_id": rt.ClientID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (c *ManagementController) HandleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")
	user, err := c.userSvc.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// ─── Token Management ─────────────────────────────────────

func (c *ManagementController) HandleListTokens(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	userID := r.URL.Query().Get("user_id")

	tokens, err := c.tokenSvc.ListTokens(clientID, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list tokens")
		return
	}
	writeJSON(w, http.StatusOK, tokens)
}

func (c *ManagementController) HandleRevokeToken(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	if err := c.tokenSvc.RevokeToken(token); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to revoke token")
		return
	}
	c.writeAudit(r, "token.revoke", "access_token", "", map[string]any{})
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// ─── MFA Management ───────────────────────────────────────

func (c *ManagementController) HandleMFAEnable(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	user, err := c.userSvc.GetUser(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	result, err := c.totpSvc.EnableMFA(userID, user.Username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to enable MFA: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret":    result.Secret,
		"qr_uri":    result.QRCodeURI,
		"qr_base64": result.QRBase64,
	})
}

func (c *ManagementController) HandleMFAVerify(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	var req struct {
		Code string `json:"code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	if err := c.totpSvc.ConfirmMFA(userID, req.Code); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_enabled"})
}

func (c *ManagementController) HandleMFAStatus(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	enabled, err := c.totpSvc.IsMFAEnabled(userID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":     userID,
		"mfa_enabled": enabled,
	})
}

func (c *ManagementController) HandleMFADisable(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "userID")

	if err := c.totpSvc.DisableMFA(userID); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to disable MFA")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "mfa_disabled"})
}

// ─── Scope Management ────────────────────────────────────

func (c *ManagementController) HandleListScopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := c.scopeRepo.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list scopes")
		return
	}
	writeJSON(w, http.StatusOK, scopes)
}

func (c *ManagementController) HandleCreateScope(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string `json:"name"`
		Description    string `json:"description"`
		ResourceServer string `json:"resource_server"`
		IsDefault      bool   `json:"is_default"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}

	scope := &models.Scope{
		Name:           req.Name,
		Description:    req.Description,
		ResourceServer: req.ResourceServer,
		IsDefault:      req.IsDefault,
	}

	if err := c.scopeRepo.Create(scope); err != nil {
		writeError(w, http.StatusConflict, "already_exists", "Scope already exists")
		return
	}

	writeJSON(w, http.StatusCreated, scope)
}

func (c *ManagementController) HandleGetScope(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	scope, err := c.scopeRepo.Get(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Scope not found")
		return
	}

	writeJSON(w, http.StatusOK, scope)
}

func (c *ManagementController) HandleDeleteScope(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	if err := c.scopeRepo.Delete(name); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to delete scope")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ─── Resource Management ────────────────────────────────────

func (c *ManagementController) HandleListResources(w http.ResponseWriter, r *http.Request) {
	resources, err := c.resourceRepo.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list resources")
		return
	}
	writeJSON(w, http.StatusOK, resources)
}

func (c *ManagementController) HandleCreateResource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URI         string   `json:"uri"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Scopes      []string `json:"scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.URI == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "uri and name are required")
		return
	}

	resource := &models.Resource{
		URI:         req.URI,
		Name:        req.Name,
		Description: req.Description,
		Scopes:      req.Scopes,
	}

	if err := c.resourceRepo.Create(resource); err != nil {
		writeError(w, http.StatusConflict, "already_exists", "Resource already exists")
		return
	}

	writeJSON(w, http.StatusCreated, resource)
}

func (c *ManagementController) HandleGetResource(w http.ResponseWriter, r *http.Request) {
	uri := chi.URLParam(r, "uri")

	resource, err := c.resourceRepo.Get(uri)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Resource not found")
		return
	}

	writeJSON(w, http.StatusOK, resource)
}

func (c *ManagementController) HandleUpdateResource(w http.ResponseWriter, r *http.Request) {
	uri := chi.URLParam(r, "uri")

	existing, err := c.resourceRepo.Get(uri)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Resource not found")
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Scopes      []string `json:"scopes"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.Scopes != nil {
		existing.Scopes = req.Scopes
	}

	if err := c.resourceRepo.Update(existing); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to update resource")
		return
	}

	writeJSON(w, http.StatusOK, existing)
}

func (c *ManagementController) HandleDeleteResource(w http.ResponseWriter, r *http.Request) {
	uri := chi.URLParam(r, "uri")

	if err := c.resourceRepo.Delete(uri); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to delete resource")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (c *ManagementController) HandleListResourceScopes(w http.ResponseWriter, r *http.Request) {
	uri := chi.URLParam(r, "uri")

	scopes, err := c.scopeRepo.ListByResource(uri)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list scopes")
		return
	}

	writeJSON(w, http.StatusOK, scopes)
}

// ─── Consent Management ────────────────────────────────────

func (c *ManagementController) HandleListConsents(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	if userID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}

	consents, err := c.consentRepo.ListByUser(userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list consents")
		return
	}

	writeJSON(w, http.StatusOK, consents)
}

func (c *ManagementController) HandleRevokeConsent(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")
	clientID := r.URL.Query().Get("client_id")

	if userID == "" || clientID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "user_id and client_id are required")
		return
	}

	var err error
	if c.grants != nil {
		err = c.grants.Revoke(userID, clientID)
	} else if c.consentRepo != nil {
		err = c.consentRepo.Delete(userID, clientID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to revoke consent")
		return
	}
	c.writeAudit(r, "consent.revoke", "client", clientID, map[string]any{"user_id": userID})

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (c *ManagementController) HandleListWebhooks(w http.ResponseWriter, r *http.Request) {
	if c.hooks == nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Webhooks are not configured")
		return
	}
	hooks, err := c.hooks.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list webhooks")
		return
	}
	writeJSON(w, http.StatusOK, hooks)
}

func (c *ManagementController) HandleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	var req webhookBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	hook, err := c.hooks.Create(service.WebhookInput{
		URL: req.URL, Secret: req.Secret, Events: req.Events, Enabled: req.Enabled, Description: req.Description,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.writeAudit(r, "webhook.create", "webhook", hook.ID, map[string]any{"url": hook.URL, "events": hook.Events})
	writeJSON(w, http.StatusCreated, hook)
}

func (c *ManagementController) HandleGetWebhook(w http.ResponseWriter, r *http.Request) {
	hook, err := c.hooks.Get(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Webhook not found")
		return
	}
	writeJSON(w, http.StatusOK, hook)
}

func (c *ManagementController) HandleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	var req webhookBody
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	hook, err := c.hooks.Update(chi.URLParam(r, "id"), service.WebhookInput{
		URL: req.URL, Secret: req.Secret, Events: req.Events, Enabled: req.Enabled, Description: req.Description,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || err.Error() == "webhook not found" {
			writeError(w, http.StatusNotFound, "not_found", "Webhook not found")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.writeAudit(r, "webhook.update", "webhook", hook.ID, map[string]any{"url": hook.URL, "events": hook.Events})
	writeJSON(w, http.StatusOK, hook)
}

func (c *ManagementController) HandleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := c.hooks.Delete(id); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Webhook not found")
		return
	}
	c.writeAudit(r, "webhook.delete", "webhook", id, map[string]any{})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (c *ManagementController) HandleTestWebhook(w http.ResponseWriter, r *http.Request) {
	if err := c.hooks.Test(chi.URLParam(r, "id")); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "not_found", "Webhook not found")
			return
		}
		writeError(w, http.StatusBadGateway, "webhook_delivery_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "delivered"})
}

func (c *ManagementController) HandleListAudit(w http.ResponseWriter, r *http.Request) {
	window, err := loginWindow(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if c.audit == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	rows, err := c.audit.List(r.URL.Query().Get("action"), r.URL.Query().Get("actor_id"), time.Now().Add(-window))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list audit logs")
		return
	}
	if rows == nil {
		rows = []repository.AuditRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

func (c *ManagementController) HandleRotateKeys(w http.ResponseWriter, r *http.Request) {
	if c.keys == nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Signing keys are not configured")
		return
	}
	if err := c.keys.Rotate(c.keyRetain); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to rotate signing keys")
		return
	}
	kids := []string{}
	for _, key := range c.keys.ToJWKS().Keys {
		kids = append(kids, key.Kid)
	}
	c.writeAudit(r, "key.rotate", "signing_key", "", map[string]any{"kids": kids})
	writeJSON(w, http.StatusOK, map[string]any{"status": "rotated", "kids": kids})
}

type webhookBody struct {
	URL         string   `json:"url"`
	Secret      string   `json:"secret"`
	Events      []string `json:"events"`
	Enabled     *bool    `json:"enabled"`
	Description string   `json:"description"`
}
