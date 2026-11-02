package controller

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
)

func (c *ManagementController) SetAccess(access *service.AccessService) {
	defer telemetry.Step("controller.ManagementController.SetAccess")()
	if c != nil {
		c.access = access
	}
}

func (c *ManagementController) requireAccess(w http.ResponseWriter) (*service.AccessService, bool) {
	defer telemetry.Step("controller.ManagementController.requireAccess")()
	if c == nil || c.access == nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Roles are not configured")
		return nil, false
	}
	return c.access, true
}

func (c *ManagementController) HandleCreateRole(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleCreateRole")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	role, err := access.CreateRole(req.Name, req.Description)
	if err != nil {
		writeRoleError(w, err)
		return
	}
	c.writeAudit(r, "role.create", "role", role.ID, map[string]any{"name": role.Name})
	writeJSON(w, http.StatusCreated, role)
}

func (c *ManagementController) HandleListRoles(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleListRoles")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	roles, err := access.ListRoles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to list roles")
		return
	}
	if roles == nil {
		roles = []*models.Role{}
	}
	writeJSON(w, http.StatusOK, roles)
}

func (c *ManagementController) HandleGetRole(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleGetRole")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	role, err := access.GetRole(chi.URLParam(r, "roleID"))
	if err != nil {
		writeRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (c *ManagementController) HandlePatchRole(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandlePatchRole")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	name, description := "", ""
	if req.Name != nil {
		name = *req.Name
	}
	if req.Description != nil {
		description = *req.Description
	}
	role, err := access.UpdateRole(chi.URLParam(r, "roleID"), name, description, req.Name != nil, req.Description != nil)
	if err != nil {
		writeRoleError(w, err)
		return
	}
	c.writeAudit(r, "role.update", "role", role.ID, map[string]any{"name": role.Name})
	writeJSON(w, http.StatusOK, role)
}

func (c *ManagementController) HandleDeleteRole(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleDeleteRole")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	roleID := chi.URLParam(r, "roleID")
	if err := access.DeleteRole(roleID); err != nil {
		writeRoleError(w, err)
		return
	}
	c.writeAudit(r, "role.delete", "role", roleID, map[string]any{})
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (c *ManagementController) HandleSetRoleScopes(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleSetRoleScopes")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	var req struct {
		Scopes []models.RoleScope `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	role, err := access.SetRoleScopes(chi.URLParam(r, "roleID"), req.Scopes)
	if err != nil {
		writeRoleError(w, err)
		return
	}
	c.writeAudit(r, "role.scopes", "role", role.ID, map[string]any{"count": len(role.Scopes)})
	writeJSON(w, http.StatusOK, role)
}

func (c *ManagementController) HandleAssignUserRole(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleAssignUserRole")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	var req struct {
		RoleID string `json:"role_id"`
		OrgID  string `json:"org_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	grant, err := access.AssignRole(chi.URLParam(r, "userID"), req.RoleID, req.OrgID)
	if err != nil {
		writeRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, grant)
}

func (c *ManagementController) HandleRemoveUserRole(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleRemoveUserRole")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	var req struct {
		RoleID string `json:"role_id"`
		OrgID  string `json:"org_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	userID := chi.URLParam(r, "userID")
	if err := access.RemoveRole(userID, req.RoleID, req.OrgID); err != nil {
		writeRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (c *ManagementController) HandleAssignUserScope(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleAssignUserScope")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	var req struct {
		Resource string `json:"resource"`
		Scope    string `json:"scope"`
		OrgID    string `json:"org_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	grant, err := access.AssignScope(chi.URLParam(r, "userID"), req.Resource, req.Scope, req.OrgID)
	if err != nil {
		writeRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, grant)
}

func (c *ManagementController) HandleRemoveUserScope(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleRemoveUserScope")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	var req struct {
		Resource string `json:"resource"`
		Scope    string `json:"scope"`
		OrgID    string `json:"org_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	if err := access.RemoveScope(chi.URLParam(r, "userID"), req.Resource, req.Scope, req.OrgID); err != nil {
		writeRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (c *ManagementController) HandleUserAccess(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleUserAccess")()
	access, ok := c.requireAccess(w)
	if !ok {
		return
	}
	body, err := access.UserAccess(chi.URLParam(r, "userID"))
	if err != nil {
		writeRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, body)
}

func writeRoleError(w http.ResponseWriter, err error) {
	defer telemetry.Step("controller.writeRoleError")()
	switch {
	case err == nil:
	case errors.Is(err, service.ErrRoleExists):
		writeError(w, http.StatusConflict, "already_exists", err.Error())
	case errors.Is(err, service.ErrUnknownRole), errors.Is(err, service.ErrGrantMissing), errors.Is(err, sql.ErrNoRows):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, service.ErrUnknownScope), errors.Is(err, service.ErrManagementGrant), errors.Is(err, service.ErrUnknownOrg):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	case strings.Contains(err.Error(), "user not found"), strings.Contains(err.Error(), "role name"):
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to update roles")
	}
}
