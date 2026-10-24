package controller

import (
	"encoding/json"
	"net/http"

	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

func (c *ManagementController) HandleImportUsers(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleImportUsers")()
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var doc service.ImportDocument
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	dry := r.URL.Query().Get("dry_run") == "true"
	result, err := c.userSvc.ImportUsers(doc, dry, c.orgs)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.writeAudit(r, "user.import", "user", "", map[string]any{
		"created": result.Created,
		"updated": result.Updated,
		"errors":  len(result.Errors),
		"dry_run": dry,
	})
	writeJSON(w, http.StatusOK, result)
}

func (c *ManagementController) HandleExportUsers(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleExportUsers")()
	secrets := r.URL.Query().Get("include_secrets") == "true"
	doc, err := c.userSvc.ExportUsers(secrets, c.orgs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to export users")
		return
	}
	if secrets {
		c.writeAudit(r, "user.export", "user", "", map[string]any{"users": len(doc.Users)})
	}
	writeJSON(w, http.StatusOK, doc)
}
