package controller

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
)

func (c *ManagementController) SetBackup(b *service.Backup) {
	defer telemetry.Step("controller.ManagementController.SetBackup")()
	if c != nil {
		c.backup = b
	}
}

func (c *ManagementController) HandleBackup(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleBackup")()
	if c == nil || c.backup == nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Backup is not configured")
		return
	}
	doc, err := c.backup.Export()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to build the backup")
		return
	}
	c.writeAudit(r, "backup.export", "backup", "", map[string]any{
		"users":   len(doc.Users),
		"clients": len(doc.Clients),
	})
	writeJSON(w, http.StatusOK, doc)
}

func (c *ManagementController) HandleRestore(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleRestore")()
	if c == nil || c.backup == nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Backup is not configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	var doc service.BackupDocument
	if err := json.NewDecoder(r.Body).Decode(&doc); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}
	dry := r.URL.Query().Get("dry_run") == "true"
	force := r.URL.Query().Get("force") == "true"
	result, err := c.backup.Restore(doc, dry, force)
	if errors.Is(err, service.ErrRestoreConflict) {
		writeError(w, http.StatusConflict, "conflict", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	c.writeAudit(r, "backup.restore", "backup", "", map[string]any{
		"dry_run": dry,
		"force":   force,
		"users":   result.Users,
		"clients": result.Clients,
	})
	writeJSON(w, http.StatusOK, result)
}
