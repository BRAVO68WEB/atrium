package oauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
)

// enforceClientDPoP requires a proof when the OAuth app forces DPoP.
// The server flag security.dpop.enabled does not turn this off.
// The bool is false when the error response has already been written.
func (h *Handler) enforceClientDPoP(w http.ResponseWriter, r *http.Request, client *models.Client) (string, bool) {
	defer telemetry.Step("oauth.Handler.enforceClientDPoP")()
	if client == nil || !client.DPoPBoundAccessTokens {
		return "", true
	}
	proof, err := h.ValidateDPoPProof(r, "")
	if err != nil || proof == nil || proof.JKT == "" {
		desc := "Failed to get JKT"
		if err != nil {
			desc = err.Error()
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", desc)
		return "", false
	}
	return proof.JKT, true
}

func (h *Handler) revokeDPoP(w http.ResponseWriter, r *http.Request, client *models.Client, token string) bool {
	defer telemetry.Step("oauth.Handler.revokeDPoP")()
	needs := client != nil && client.DPoPBoundAccessTokens
	proofToken := ""
	var boundJKT string
	if at, err := h.tokenRepo.GetAccessToken(token); err == nil && (at.TokenType == "DPoP" || at.DPoPJKT != "") {
		needs = true
		proofToken = token
		boundJKT = at.DPoPJKT
	} else if rt, err := h.tokenRepo.GetRefreshToken(token); err == nil && rt.AccessToken != "" {
		if at, err := h.tokenRepo.GetAccessTokenByKey(rt.AccessToken); err == nil && (at.TokenType == "DPoP" || at.DPoPJKT != "") {
			needs = true
			proofToken = token
			boundJKT = at.DPoPJKT
		}
	}
	if !needs {
		return true
	}
	// A confidential client has already authenticated as the token owner.
	// Presenting the token to a resource still requires the DPoP proof.
	if client != nil && client.TokenEndpointAuthMethod != "none" && client.Secret != "" && r.Header.Get("DPoP") == "" {
		return true
	}
	proof, err := h.ValidateDPoPProof(r, proofToken)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_token", err.Error())
		return false
	}
	if boundJKT != "" && (proof == nil || proof.JKT != boundJKT) {
		writeTokenError(w, http.StatusBadRequest, "invalid_token", "DPoP key does not match the token")
		return false
	}
	return true
}

// boundRefreshDPoP keeps a refreshed token on the key that issued it.
// A client that requires DPoP does not upgrade an older unbound session:
// the user signs in again and gets a new key.
func (h *Handler) boundRefreshDPoP(w http.ResponseWriter, r *http.Request, client *models.Client, boundJKT string) (string, bool) {
	defer telemetry.Step("oauth.Handler.boundRefreshDPoP")()
	if client != nil && client.DPoPBoundAccessTokens && boundJKT == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Session is not bound to a device key. Sign in again.")
		return "", false
	}
	if (client == nil || !client.DPoPBoundAccessTokens) && boundJKT == "" {
		return "", true
	}
	proof, err := h.ValidateDPoPProof(r, "")
	if err != nil || proof == nil || proof.JKT == "" {
		desc := "Failed to get JKT"
		if err != nil {
			desc = err.Error()
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", desc)
		return "", false
	}
	if boundJKT != "" && proof.JKT != boundJKT {
		writeTokenError(w, http.StatusBadRequest, "invalid_dpop_proof", "DPoP key does not match the token")
		return "", false
	}
	return proof.JKT, true
}

func boundTokenType(client *models.Client) string {
	defer telemetry.Step("oauth.boundTokenType")()
	if client != nil && client.DPoPBoundAccessTokens {
		return "DPoP"
	}
	return "Bearer"
}

// proofURIs is the request URI, then the public issuer URI when they differ.
// Resource servers and this API call the token endpoint on an internal host.
// The browser signs the public issuer. Replay is recorded only after htu matches,
// so a mismatch on the internal host can be retried safely.
func proofURIs(scheme, host, path, issuer string) []string {
	primary := fmt.Sprintf("%s://%s%s", scheme, host, path)
	public := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if public == "" {
		return []string{primary}
	}
	candidate := public + path
	if candidate == primary {
		return []string{primary}
	}
	return []string{primary, candidate}
}

func (h *Handler) ValidateDPoPProof(r *http.Request, accessToken string) (*service.DPoPProof, error) {
	defer telemetry.Step("oauth.Handler.ValidateDPoPProof")()
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return nil, fmt.Errorf("DPoP header is required")
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	issuer := ""
	if h.cfg != nil {
		issuer = h.cfg.Security.Issuer
	}
	var last error
	for i, uri := range proofURIs(scheme, r.Host, r.URL.Path, issuer) {
		proof, err := h.dpopSvc.ValidateDPoPProof(r.Context(), dpopHeader, r.Method, uri, accessToken)
		if err == nil {
			return proof, nil
		}
		last = err
		if i == 0 && strings.Contains(err.Error(), "htu mismatch") {
			continue
		}
		return nil, err
	}
	if last == nil {
		last = fmt.Errorf("DPoP proof is invalid")
	}
	return nil, last
}
