package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/auth"
)

type TokenHandler struct {
	AuthService auth.Service
}

func (h TokenHandler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "failed to parse form", nil)
		return
	}

	grantType := strings.TrimSpace(r.FormValue("grant_type"))
	if grantType != "client_credentials" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only client_credentials is supported in phase-1", nil)
		return
	}

	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := strings.TrimSpace(r.FormValue("client_secret"))
	if clientID == "" {
		if u, p, ok := r.BasicAuth(); ok {
			clientID = strings.TrimSpace(u)
			clientSecret = strings.TrimSpace(p)
		}
	}
	if clientID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required", nil)
		return
	}
	requestedScopes := parseScopeParam(r.FormValue("scope"))
	issued, err := h.AuthService.IssueClientCredentials(r.Context(), clientID, clientSecret, requestedScopes)
	if err != nil {
		status := http.StatusInternalServerError
		code := "internal_error"
		switch {
		case errors.Is(err, auth.ErrInvalidClientID):
			status, code = http.StatusBadRequest, "invalid_client"
		case errors.Is(err, auth.ErrInvalidClientCredentials):
			status, code = http.StatusUnauthorized, "invalid_client"
		case errors.Is(err, auth.ErrClientDisabled):
			status, code = http.StatusForbidden, "access_denied"
		case errors.Is(err, auth.ErrNoScopeGranted):
			status, code = http.StatusForbidden, "invalid_scope"
		}
		writeOAuthError(w, status, code, err.Error(), nil)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": issued.Value,
		"token_type":   "Bearer",
		"expires_in":   int(issued.ExpiresAt.Sub(issued.IssuedAt).Seconds()),
		"scope":        strings.Join(issued.Scopes, " "),
	})
}

func parseScopeParam(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	return strings.Fields(raw)
}

func writeOAuthError(w http.ResponseWriter, status int, code, message string, details map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":    code,
		"message": message,
		"details": details,
	})
}
