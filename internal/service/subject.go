package service

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/oidc"
	"github.com/bravo68web/atrium/internal/telemetry"
)

// ValidateSubjectType checks public and pairwise client settings.
// A pairwise client without a sector URI must use one redirect host.
func ValidateSubjectType(client *models.Client) error {
	defer telemetry.Step("service.ValidateSubjectType")()
	if client == nil {
		return fmt.Errorf("client is required")
	}
	switch strings.ToLower(strings.TrimSpace(client.SubjectType)) {
	case "", "public":
		client.SubjectType = "public"
		return nil
	case "pairwise":
		client.SubjectType = "pairwise"
		if strings.TrimSpace(client.SectorIdentifierURI) != "" {
			parsed, err := url.Parse(strings.TrimSpace(client.SectorIdentifierURI))
			if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
				return fmt.Errorf("sector_identifier_uri must be an absolute https url")
			}
			client.SectorIdentifierURI = parsed.String()
			return nil
		}
		_, err := oidc.SectorHost(client.RedirectURIs)
		return err
	default:
		return fmt.Errorf("subject_type must be public or pairwise")
	}
}
