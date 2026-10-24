package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/cache"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

const sectorCacheTTL = 5 * time.Minute

// PairwiseIdentifier is the PPID for one sector and local account.
// The salt is the server secret. Changing it changes every pairwise sub.
func PairwiseIdentifier(sectorID, userID, salt string) string {
	defer telemetry.Step("oidc.PairwiseIdentifier")()
	sum := sha256.Sum256([]byte(sectorID + "\n" + userID + "\n" + salt))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Subject returns the local user id for a public client and the PPID for a pairwise client.
func (h *Handler) Subject(client *models.Client, userID string) (string, error) {
	defer telemetry.Step("oidc.Handler.Subject")()
	if userID == "" || client == nil || !strings.EqualFold(client.SubjectType, "pairwise") {
		return userID, nil
	}
	salt := ""
	if h != nil && h.cfg != nil {
		salt = h.cfg.OIDC.PairwiseSalt
	}
	if salt == "" {
		return "", fmt.Errorf("oidc.pairwise_salt is required")
	}
	sector, err := h.sectorID(client)
	if err != nil {
		return "", err
	}
	ppid := PairwiseIdentifier(sector, userID, salt)
	if err := h.rememberPairwise(sector, ppid, userID); err != nil {
		return "", err
	}
	return ppid, nil
}

func (h *Handler) SubjectFor(clientID, userID string) (string, error) {
	defer telemetry.Step("oidc.Handler.SubjectFor")()
	if userID == "" {
		return clientID, nil
	}
	if h == nil || h.clients == nil {
		return userID, nil
	}
	client, err := h.clients.GetByID(clientID)
	if err != nil || client == nil {
		return userID, nil
	}
	return h.Subject(client, userID)
}

func (h *Handler) sectorID(client *models.Client) (string, error) {
	defer telemetry.Step("oidc.Handler.sectorID")()
	if strings.TrimSpace(client.SectorIdentifierURI) != "" {
		raw := strings.TrimSpace(client.SectorIdentifierURI)
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" || parsed.Scheme != "https" {
			return "", fmt.Errorf("sector_identifier_uri must be an absolute https url")
		}
		listed, err := h.sectorRedirects(raw)
		if err != nil {
			return "", err
		}
		allowed := map[string]bool{}
		for _, item := range listed {
			allowed[item] = true
		}
		for _, redirect := range client.RedirectURIs {
			if !allowed[redirect] {
				return "", fmt.Errorf("redirect uri %s is missing from the sector identifier document", redirect)
			}
		}
		return parsed.Hostname(), nil
	}
	return SectorHost(client.RedirectURIs)
}

// SectorHost is the shared redirect host for a pairwise client without a sector URI.
func SectorHost(redirects []string) (string, error) {
	defer telemetry.Step("oidc.SectorHost")()
	host := ""
	for _, raw := range redirects {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return "", fmt.Errorf("pairwise client has an invalid redirect uri")
		}
		name := strings.ToLower(parsed.Hostname())
		if host == "" {
			host = name
			continue
		}
		if host != name {
			return "", fmt.Errorf("pairwise client redirects must share one host or set sector_identifier_uri")
		}
	}
	if host == "" {
		return "", fmt.Errorf("pairwise client requires a redirect uri")
	}
	return host, nil
}

func (h *Handler) sectorRedirects(rawURL string) ([]string, error) {
	defer telemetry.Step("oidc.Handler.sectorRedirects")()
	if h != nil && h.sectorCache != nil {
		if cached, ok, err := h.sectorCache.Get(context.Background(), "sector:"+rawURL); err == nil && ok {
			var listed []string
			if err := json.Unmarshal(cached, &listed); err == nil {
				return listed, nil
			}
		}
	}
	if h == nil || h.fetchSector == nil {
		return nil, fmt.Errorf("sector identifier document cannot be fetched")
	}
	body, err := h.fetchSector(context.Background(), rawURL)
	if err != nil {
		return nil, err
	}
	var listed []string
	if err := json.Unmarshal(body, &listed); err != nil {
		return nil, fmt.Errorf("sector identifier document is not a json array of urls")
	}
	if h.sectorCache != nil {
		_ = h.sectorCache.Set(context.Background(), "sector:"+rawURL, body, sectorCacheTTL)
	}
	return listed, nil
}

func (h *Handler) rememberPairwise(sector, ppid, userID string) error {
	defer telemetry.Step("oidc.Handler.rememberPairwise")()
	if h == nil || h.db == nil {
		return nil
	}
	query := `INSERT INTO pairwise_subjects (sector_id, ppid, user_id) VALUES (?, ?, ?) ON CONFLICT (sector_id, ppid) DO NOTHING`
	if h.db.Dialect() == "sqlite" {
		query = `INSERT OR IGNORE INTO pairwise_subjects (sector_id, ppid, user_id) VALUES (?, ?, ?)`
	}
	_, err := h.db.Exec(query, sector, ppid, userID)
	return err
}

// SetSectorFetch supplies the SSRF-safe GET used for sector identifier documents.
func (h *Handler) SetSectorFetch(fn func(ctx context.Context, rawURL string) ([]byte, error)) {
	defer telemetry.Step("oidc.Handler.SetSectorFetch")(

	// SetSectorCache stores sector documents for five minutes.
	)
	if h != nil {
		h.fetchSector = fn
	}
}

func (h *Handler) SetSectorCache(c cache.Cache) {
	defer telemetry.Step("oidc.Handler.SetSectorCache")()
	if h != nil {
		h.sectorCache = c
	}
}
