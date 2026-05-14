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
		"issuer":                                h.Config.OAuth.Issuer,
		"jwks_uri":                              h.Config.OAuth.Issuer + "/.well-known/jwks.json",
		"token_endpoint":                        h.Config.OAuth.Issuer + "/oauth/token",
		"authorization_endpoint":                h.Config.OAuth.Issuer + "/oauth/authorize",
		"registration_endpoint":                 h.Config.OAuth.Issuer + "/oauth/register",
		"scopes_supported":                      h.scopesSupported(),
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"response_types_supported":              []string{"code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
	})
	_ = r
}

func (h OIDCHandler) OAuthAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                h.Config.OAuth.Issuer,
		"authorization_endpoint":                h.Config.OAuth.Issuer + "/oauth/authorize",
		"token_endpoint":                        h.Config.OAuth.Issuer + "/oauth/token",
		"registration_endpoint":                 h.Config.OAuth.Issuer + "/oauth/register",
		"jwks_uri":                              h.Config.OAuth.Issuer + "/oauth/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"scopes_supported":                      h.scopesSupported(),
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

func (h OIDCHandler) scopesSupported() []string {
	if len(h.Config.OAuth.SupportedScopes) > 0 {
		return h.Config.OAuth.SupportedScopes
	}
	return []string{"openid", "profile", "email", "mcp:tools", "mcp:read", "mcp:write", "offline_access"}
}
