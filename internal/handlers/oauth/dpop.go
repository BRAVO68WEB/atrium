package oauth

import (
	"fmt"
	"net/http"

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
		proofToken = at.Token
		boundJKT = at.DPoPJKT
	} else if rt, err := h.tokenRepo.GetRefreshToken(token); err == nil && rt.AccessToken != "" {
		if at, err := h.tokenRepo.GetAccessToken(rt.AccessToken); err == nil && (at.TokenType == "DPoP" || at.DPoPJKT != "") {
			needs = true
			proofToken = at.Token
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
// A client that requires DPoP still needs a proof when the old token had none.
func (h *Handler) boundRefreshDPoP(w http.ResponseWriter, r *http.Request, client *models.Client, boundJKT string) (string, bool) {
	defer telemetry.Step("oauth.Handler.boundRefreshDPoP")()
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

func (h *Handler) ValidateDPoPProof(r *http.Request, accessToken string) (*service.DPoPProof, error) {
	defer telemetry.Step("oauth.Handler.ValidateDPoPProof")()
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		return nil, fmt.Errorf("DPoP header is required")
	}

	// Build full URI for DPoP validation
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fullURI := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)

	return h.dpopSvc.ValidateDPoPProof(r.Context(), dpopHeader, r.Method, fullURI, accessToken)
}
