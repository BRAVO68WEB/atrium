package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

// CIMDDocument is a Client ID Metadata Document.
type CIMDDocument struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scope        string   `json:"scope"`
}

// FetchCIMD loads a metadata document. The caller checks client_id and redirects.
func FetchCIMD(ctx context.Context, cfg *config.Config, rawURL string) (*CIMDDocument, error) {
	defer telemetry.Step("service.FetchCIMD")()
	body, status, err := FetchSafe(ctx, cfg, http.MethodGet, rawURL, nil, nil)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("metadata document returned %d", status)
	}
	var doc CIMDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("metadata document is not json")
	}
	return &doc, nil
}

// ClientFromCIMD builds a public client from a metadata document.
func ClientFromCIMD(doc *CIMDDocument) *models.Client {
	defer telemetry.Step("service.ClientFromCIMD")()
	grants := doc.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	redirects := doc.RedirectURIs
	if redirects == nil {
		redirects = []string{}
	}
	name := doc.ClientName
	if name == "" {
		name = doc.ClientID
	}
	return &models.Client{
		ID:                               doc.ClientID,
		Name:                             name,
		RedirectURIs:                     redirects,
		GrantTypes:                       grants,
		Scopes:                           StripManagement(strings.Fields(doc.Scope)),
		TokenEndpointAuthMethod:          "none",
		RegistrationSource:               "cimd",
		CIMDEnabled:                      true,
		PostLogoutRedirectURIs:           []string{},
		BackchannelLogoutSessionRequired: true,
	}
}
