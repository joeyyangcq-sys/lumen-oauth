package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/joey/lumen-oauth/internal/application/invite"
)

type InviteHandler struct {
	Service invite.Service
}

func (h InviteHandler) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}
	out, err := h.Service.CreateInvitation(r.Context(), req.Email, req.Role)
	if err != nil {
		switch {
		case errors.Is(err, invite.ErrInvalidEmail):
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":       out.Code,
		"email":      out.Email,
		"role":       out.Role,
		"expires_at": out.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
}

func (h InviteHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	var req struct {
		Code    string `json:"code"`
		Subject string `json:"subject"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}
	out, err := h.Service.AcceptInvitation(r.Context(), req.Code, req.Subject)
	if err != nil {
		switch {
		case errors.Is(err, invite.ErrInvalidInviteCode), errors.Is(err, invite.ErrInviteNotFound):
			writeOAuthError(w, http.StatusBadRequest, "invalid_invite", err.Error(), nil)
		case errors.Is(err, invite.ErrInviteUsed), errors.Is(err, invite.ErrInviteExpired), errors.Is(err, invite.ErrInviteRevoked):
			writeOAuthError(w, http.StatusConflict, "invite_not_usable", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"subject": out.Subject,
		"role":    out.Role,
		"status":  "accepted",
	})
}
