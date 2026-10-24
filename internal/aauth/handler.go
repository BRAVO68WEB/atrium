package aauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/go-chi/chi/v5"
)

// Handler serves AAuth discovery. Token endpoints arrive in later phases.
type Handler struct {
	cfg *config.Config
	key signingKey
}

// New loads the Ed25519 key and prepares discovery. cfg.AAuth.Enabled must
// already be true and the issuers normalized.
func New(cfg *config.Config, db database.SQL) (*Handler, error) {
	defer telemetry.Step("aauth.New")()
	key, err := loadOrCreateKey(db)
	if err != nil {
		return nil, err
	}
	return &Handler{cfg: cfg, key: key}, nil
}

type document struct {
	issuer string
	name   string
	body   map[string]any
}

func (h *Handler) documents() []document {
	defer telemetry.Step("aauth.Handler.documents")()
	aa := h.cfg.AAuth
	return []document{
		{issuer: aa.APIssuer, name: "aauth-agent.json", body: map[string]any{
			"issuer":   aa.APIssuer,
			"jwks_uri": joinIssuer(aa.APIssuer, "/aauth/jwks"),
		}},
		{issuer: aa.PSIssuer, name: "aauth-person.json", body: map[string]any{
			"issuer":   aa.PSIssuer,
			"jwks_uri": joinIssuer(aa.PSIssuer, "/aauth/jwks"),
		}},
		{issuer: aa.ASIssuer, name: "aauth-access.json", body: map[string]any{
			"issuer":   aa.ASIssuer,
			"jwks_uri": joinIssuer(aa.ASIssuer, "/aauth/jwks"),
		}},
		{issuer: aa.ResourceIssuer, name: "aauth-resource.json", body: map[string]any{
			"issuer":   aa.ResourceIssuer,
			"jwks_uri": joinIssuer(aa.ResourceIssuer, "/aauth/jwks"),
		}},
	}
}

// Mount registers discovery on mux. The same JWKS is served once per
// distinct issuer path.
func (h *Handler) Mount(mux *chi.Mux) {
	defer telemetry.Step("aauth.Handler.Mount")()
	if h == nil || mux == nil {
		return
	}
	jwksSeen := map[string]struct{}{}
	for _, doc := range h.documents() {
		doc := doc
		mux.Get(wellKnownPath(doc.issuer, doc.name), func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, doc.body)
		})
		jwks := jwksPath(doc.issuer)
		if _, ok := jwksSeen[jwks]; ok {
			continue
		}
		jwksSeen[jwks] = struct{}{}
		mux.Get(jwks, h.serveJWKS)
	}
}

func (h *Handler) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	defer telemetry.Step("aauth.Handler.serveJWKS")()
	writeJSON(w, map[string]any{
		"keys": []map[string]string{{
			"kty": "OKP",
			"crv": "Ed25519",
			"alg": "Ed25519",
			"use": "sig",
			"kid": h.key.KID,
			"x":   h.key.PublicB64,
		}},
	})
}

func writeJSON(w http.ResponseWriter, body any) {
	defer telemetry.Step("aauth.writeJSON")()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(body)
}

func issuerPath(issuer string) string {
	defer telemetry.Step("aauth.issuerPath")()
	parsed, err := url.Parse(issuer)
	if err != nil {
		return ""
	}
	return strings.TrimRight(parsed.Path, "/")
}

func wellKnownPath(issuer, name string) string {
	defer telemetry.Step("aauth.wellKnownPath")()
	return issuerPath(issuer) + "/.well-known/" + name
}

func jwksPath(issuer string) string {
	defer telemetry.Step("aauth.jwksPath")()
	return issuerPath(issuer) + "/aauth/jwks"
}

func joinIssuer(issuer, path string) string {
	defer telemetry.Step("aauth.joinIssuer")()
	return strings.TrimRight(issuer, "/") + path
}
