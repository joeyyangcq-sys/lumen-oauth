package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

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
	if out.SessionID != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "lumen_session",
			Value:    out.SessionID,
			Path:     "/",
			Expires:  out.SessionExpiresAt,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   r.TLS != nil,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": out.AccessToken.Value,
		"csrf_token":   out.CSRFToken,
		"token_type":   "Bearer",
		"expires_in":   int(out.AccessToken.ExpiresAt.Sub(out.AccessToken.IssuedAt).Seconds()),
		"scope":        strings.Join(out.AccessToken.Scopes, " "),
		"user":         out.User,
	})
}

func (h AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	cookie, err := r.Cookie("lumen_session")
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		writeOAuthError(w, http.StatusUnauthorized, "login_required", "missing session", nil)
		return
	}
	if err := h.Service.ValidateCSRF(r.Context(), cookie.Value, r.Header.Get("X-CSRF-Token")); err != nil {
		writeOAuthError(w, http.StatusForbidden, "csrf_required", "invalid csrf token", nil)
		return
	}
	if err := h.Service.RevokeSession(r.Context(), cookie.Value); err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "login_required", err.Error(), nil)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "lumen_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
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
