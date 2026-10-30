package controller

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
)

func (c *ManagementController) SetClientKeys(keys *service.ClientKeyService) {
	defer telemetry.Step("controller.ManagementController.SetClientKeys")()
	if c != nil {
		c.clientKeys = keys
	}
}

func (c *ManagementController) HandleResetClientSecret(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleResetClientSecret")()
	clientID := chi.URLParam(r, "clientID")
	if c.managementClient(clientID) {
		writeError(w, http.StatusForbidden, "forbidden", "The management client is not editable")
		return
	}
	secret, err := c.clientSvc.ResetSecret(clientID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "Client not found")
		return
	}
	c.writeAudit(r, "client.secret.reset", "client", clientID, map[string]any{})
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret})
}

func (c *ManagementController) HandleCreateClientKey(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleCreateClientKey")()
	c.writeClientKey(w, r, false)
}

func (c *ManagementController) HandleRotateClientKey(w http.ResponseWriter, r *http.Request) {
	defer telemetry.Step("controller.ManagementController.HandleRotateClientKey")()
	c.writeClientKey(w, r, true)
}

func (c *ManagementController) writeClientKey(w http.ResponseWriter, r *http.Request, rotate bool) {
	if c.clientKeys == nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Signing keys are not configured")
		return
	}
	clientID := chi.URLParam(r, "clientID")
	if c.managementClient(clientID) {
		writeError(w, http.StatusForbidden, "forbidden", "The management client is not editable")
		return
	}
	var result service.ClientKeyResult
	var err error
	if rotate {
		result, err = c.clientKeys.Rotate(clientID)
	} else {
		result, err = c.clientKeys.Create(clientID)
	}
	if err != nil {
		writeClientKeyError(w, err)
		return
	}
	client, err := c.clientSvc.GetClient(clientID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to load client")
		return
	}
	client.Secret = ""
	client.SigningKid = result.Kid
	client.SigningAlg = result.Alg
	action := "client.key.create"
	if rotate {
		action = "client.key.rotate"
	}
	c.writeAudit(r, action, "client", clientID, map[string]any{"kid": result.Kid, "alg": result.Alg})
	status := http.StatusCreated
	if rotate {
		status = http.StatusOK
	}
	writeJSON(w, status, map[string]any{
		"kid":         result.Kid,
		"alg":         result.Alg,
		"jwks_uri":    result.JWKSURI,
		"private_pem": result.PrivatePEM,
		"client":      client,
	})
}

func (c *ManagementController) annotateSigningKey(clientID string, kid, alg *string) error {
	if c.clientKeys == nil {
		return nil
	}
	activeKid, activeAlg, ok, err := c.clientKeys.Active(clientID)
	if err != nil || !ok {
		return err
	}
	*kid = activeKid
	*alg = activeAlg
	return nil
}

func writeClientKeyError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrClientNotFound):
		writeError(w, http.StatusNotFound, "not_found", "Client not found")
	case errors.Is(err, service.ErrClientKeyExists):
		writeError(w, http.StatusConflict, "already_exists", "This application already has a signing key. Rotate it to create another.")
	case errors.Is(err, service.ErrClientKeyMissing):
		writeError(w, http.StatusNotFound, "not_found", "This application has no signing key")
	default:
		writeError(w, http.StatusInternalServerError, "server_error", "Failed to update the signing key")
	}
}
