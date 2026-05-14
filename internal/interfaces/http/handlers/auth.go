package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/auth"
)

type AuthHandler struct {
	Service auth.Service
}

func (h AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}
	out, err := h.Service.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrInvalidCredentials):
			writeOAuthError(w, http.StatusUnauthorized, "invalid_credentials", err.Error(), nil)
		case errors.Is(err, auth.ErrUserDisabled):
			writeOAuthError(w, http.StatusForbidden, "user_disabled", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": out.AccessToken.Value,
		"token_type":   "Bearer",
		"expires_in":   int(out.AccessToken.ExpiresAt.Sub(out.AccessToken.IssuedAt).Seconds()),
		"scope":        strings.Join(out.AccessToken.Scopes, " "),
		"user":         out.User,
	})
}

func (h AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required", nil)
		return
	}
	out, err := h.Service.Me(r.Context(), r.Header.Get("Authorization"))
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "unauthorized", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
