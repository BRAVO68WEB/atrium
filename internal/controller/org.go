package controller

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/bravo68web/atrium/internal/auth"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/go-chi/chi/v5"
)

func (c *ManagementController) SetOrgs(orgs *service.OrgService) {
	defer telemetry.Step("controller.ManagementController.SetOrgs")()
	if c != nil {
		c.orgs = orgs
	}
}

func (c *ManagementController) requireOrgs(w http.ResponseWriter, r *http.Request) (*models.Client, bool) {
	defer telemetry.Step("controller.ManagementController.requireOrgs")()
	if c == nil || c.orgs == nil || !c.orgs.Enabled() {
		writeError(w, http.StatusForbidden, "org_disabled", "organizations are disabled")
		return nil, false
	}
	tok := auth.TokenFrom(r.Context())
	if tok == nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "management token required")
		return nil, false
	}
	client, err := c.clientSvc.GetClient(tok.ClientID)
	if err != nil || client == nil {
		writeError(w, http.StatusForbidden, "insufficient_scope", "management client not found")
		return nil, false
	}
	return client, true
}

func (c *ManagementController) orgAllowed(w http.ResponseWriter, client *models.Client, org *models.Organization) bool {
	defer telemetry.Step("controller.ManagementController.orgAllowed")()
	if client.OrgID == "" || client.OrgID == org.ID {
		return true
	}
	writeError(w, http.StatusForbidden, "insufficient_scope", "management client is limited to its organization")
	return false
}

func (c *ManagementController) HandleCreateOrg(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleCreateOrg")()
	client, ok := c.requireOrgs(w, r)
	if !ok {
		return
	}
	if client.OrgID != "" {
		writeError(w, http.StatusForbidden, "insufficient_scope", "an organization client cannot create organizations")
		return
	}
	var req struct {
		Name    string   `json:"name"`
		Slug    string   `json:"slug"`
		Domains []string `json:"domains"`
		LogoURL string   `json:"logo_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	org, err := c.orgs.Create(req.Name, req.Slug, req.Domains, req.LogoURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.writeAudit(r, "org.create", "org", org.ID, map[string]any{"slug": org.Slug})
	writeJSON(w, http.StatusCreated, org)
}

func (c *ManagementController) HandleListOrgs(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleListOrgs")()
	client, ok := c.requireOrgs(w, r)
	if !ok {
		return
	}
	if client.OrgID != "" {
		org, err := c.orgs.Get(client.OrgID)
		if err != nil {
			writeError(w, http.StatusNotFound, "not_found", "organization not found")
			return
		}
		writeJSON(w, http.StatusOK, []*models.Organization{org})
		return
	}
	orgs, err := c.orgs.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to list organizations")
		return
	}
	writeJSON(w, http.StatusOK, orgs)
}

func (c *ManagementController) HandleGetOrg(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleGetOrg")()
	client, ok := c.requireOrgs(w, r)
	if !ok {
		return
	}
	org, err := c.orgs.Get(chi.URLParam(r, "orgID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "organization not found")
		return
	}
	if !c.orgAllowed(w, client, org) {
		return
	}
	writeJSON(w, http.StatusOK, org)
}

func (c *ManagementController) HandleAddOrgDomain(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleAddOrgDomain")()
	client, org, ok := c.loadManagedOrg(w, r)
	if !ok {
		return
	}
	if client.OrgID != "" {
		writeError(w, http.StatusForbidden, "insufficient_scope", "an organization client cannot change domains")
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	if err := c.orgs.AddDomain(org.ID, req.Domain); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	updated, err := c.orgs.Get(org.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to load organization")
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (c *ManagementController) HandleAddOrgMember(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleAddOrgMember")()
	_, org, ok := c.loadManagedOrg(w, r)
	if !ok {
		return
	}
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	if strings.TrimSpace(req.UserID) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "user_id is required")
		return
	}
	if err := c.orgs.AddMember(org.ID, req.UserID, req.Role); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, service.ErrOrgInvalid) {
			status = http.StatusNotFound
		}
		writeError(w, status, "invalid_request", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"org_id": org.ID, "user_id": req.UserID, "role": defaultRole(req.Role)})
}

func (c *ManagementController) loadManagedOrg(w http.ResponseWriter, r *http.Request) (*models.Client, *models.Organization, bool) {
	defer telemetry.Step("controller.ManagementController.loadManagedOrg")()
	client, ok := c.requireOrgs(w, r)
	if !ok {
		return nil, nil, false
	}
	org, err := c.orgs.Get(chi.URLParam(r, "orgID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "organization not found")
		return nil, nil, false
	}
	if !c.orgAllowed(w, client, org) {
		return nil, nil, false
	}
	return client, org, true
}

func defaultRole(role string) string {
	defer telemetry.Step("controller.defaultRole")()
	if role == "" {
		return "member"
	}
	return role
}
