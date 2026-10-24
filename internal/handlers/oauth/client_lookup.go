package oauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

const cimdTTL = 5 * time.Minute

func (h *Handler) cimdGet(ctx context.Context, id string) (*models.Client, bool) {
	defer telemetry.Step("oauth.Handler.cimdGet")()
	if h == nil || h.cimd == nil {
		return nil, false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	raw, ok, err := h.cimd.Get(ctx, "cimd:"+id)
	if err != nil {
		log.Printf("cache cimd: %v", err)
		return nil, false
	}
	if !ok {
		return nil, false
	}
	var client models.Client
	if err := json.Unmarshal(raw, &client); err != nil {
		return nil, false
	}
	return &client, true
}

func (h *Handler) cimdPut(ctx context.Context, client *models.Client) {
	defer telemetry.Step("oauth.Handler.cimdPut")()
	if h == nil || h.cimd == nil || client == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	raw, err := json.Marshal(client)
	if err != nil {
		return
	}
	if err := h.cimd.Set(ctx, "cimd:"+client.ID, raw, cimdTTL); err != nil {
		log.Printf("cache cimd: %v", err)
	}
}

func (h *Handler) SetAudit(a *service.AuditLog) {
	defer telemetry.Step("oauth.Handler.SetAudit")()
	if h != nil {
		h.audit = a
	}
}

// resolveClient loads a client for authorize and token requests.
// An HTTPS client_id is a Client ID Metadata Document.
// A DCR client is unauthorized unless the tenant and the row both allow it.
func (h *Handler) resolveClient(ctx context.Context, clientID, redirectURI string) (*models.Client, string, string) {
	defer telemetry.Step("oauth.Handler.resolveClient")()
	if clientID == "" {
		return nil, "invalid_client", "Client not found"
	}
	if isCIMDURL(clientID) {
		return h.resolveCIMD(ctx, clientID, redirectURI)
	}
	client, err := h.clientRepo.GetByID(clientID)
	if err != nil || client == nil {
		return nil, "invalid_client", "Client not found"
	}
	if code, desc := h.gateDCR(client); code != "" {
		return nil, code, desc
	}
	return client, "", ""
}

func (h *Handler) gateDCR(client *models.Client) (string, string) {
	defer telemetry.Step("oauth.Handler.gateDCR")()
	source := client.RegistrationSource
	if source == "" {
		source = "management"
	}
	if source != "dcr" {
		return "", ""
	}
	tenant := h.cfg != nil && h.cfg.Registration.DCREnabled
	if !tenant || !client.DCREnabled {
		return "unauthorized_client", "Dynamically registered client is disabled"
	}
	return "", ""
}

func isCIMDURL(id string) bool {
	defer telemetry.Step("oauth.isCIMDURL")()
	parsed, err := url.Parse(id)
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

func (h *Handler) resolveCIMD(ctx context.Context, clientID, redirectURI string) (*models.Client, string, string) {
	defer telemetry.Step("oauth.Handler.resolveCIMD")()
	if h.cfg == nil || !h.cfg.Registration.CIMDEnabled {
		return nil, "invalid_client", "Client ID metadata documents are disabled"
	}
	existing, err := h.clientRepo.GetByID(clientID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, "server_error", "Failed to load client"
	}
	if err == nil && existing != nil && !existing.CIMDEnabled {
		return nil, "invalid_client", "Client ID metadata document is disabled"
	}
	if cached, ok := h.cimdGet(ctx, clientID); ok {
		if redirectURI != "" && !containsString(cached.RedirectURIs, redirectURI) {
			return nil, "invalid_request", "redirect_uri is not listed in the client metadata"
		}
		return cached, "", ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	doc, err := service.FetchCIMD(ctx, h.cfg, clientID)
	if err != nil || doc == nil {
		return nil, "invalid_client", "Failed to fetch client metadata"
	}
	if doc.ClientID != clientID {
		return nil, "invalid_client", "client_id in the metadata document does not match the URL"
	}
	if redirectURI != "" && !containsString(doc.RedirectURIs, redirectURI) {
		return nil, "invalid_request", "redirect_uri is not listed in the client metadata"
	}
	client := service.ClientFromCIMD(doc)
	now := time.Now()
	client.UpdatedAt = now
	if existing != nil {
		client.CreatedAt = existing.CreatedAt
		if err := h.clientRepo.Update(client); err != nil {
			return nil, "server_error", "Failed to store client metadata"
		}
	} else {
		client.CreatedAt = now
		if err := h.clientRepo.Create(client); err != nil {
			return nil, "server_error", "Failed to store client metadata"
		}
	}
	h.cimdPut(ctx, client)
	if h.audit != nil {
		h.audit.Write("system", "cimd", "client.cimd", "client", client.ID, nil, map[string]any{"name": client.Name})
	}
	return client, "", ""
}

func (h *Handler) requireClient(ctx context.Context, w http.ResponseWriter, clientID, redirectURI string, missingStatus int) (*models.Client, bool) {
	defer telemetry.Step("oauth.Handler.requireClient")()
	client, code, desc := h.resolveClient(ctx, clientID, redirectURI)
	if code == "" {
		return client, true
	}
	status := missingStatus
	switch code {
	case "unauthorized_client", "invalid_request":
		status = http.StatusBadRequest
	case "server_error":
		status = http.StatusInternalServerError
	}
	writeTokenError(w, status, code, desc)
	return nil, false
}
