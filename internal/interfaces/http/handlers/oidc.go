package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/joey/lumen-oauth/internal/config"
	"github.com/joey/lumen-oauth/internal/infrastructure/jwks"
)

type OIDCHandler struct {
	Config       config.Config
	JWKSProvider jwks.Provider
}

func (h OIDCHandler) Discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                   h.Config.OAuth.Issuer,
		"jwks_uri":                 h.Config.OAuth.Issuer + "/.well-known/jwks.json",
		"token_endpoint":           h.Config.OAuth.Issuer + "/oauth/token",
		"registration_endpoint":    h.Config.OAuth.Issuer + "/connect/register",
		"scopes_supported":         []string{"routes:read", "routes:write", "admin:dangerous"},
		"grant_types_supported":    []string{"client_credentials", "authorization_code"},
		"response_types_supported": []string{"code"},
	})
	_ = r
}

func (h OIDCHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	resp, err := h.JWKSProvider.PublicJWKS(r.Context())
	if err != nil {
		http.Error(w, "failed to build jwks", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
