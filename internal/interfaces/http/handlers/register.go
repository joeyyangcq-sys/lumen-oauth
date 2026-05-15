package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/joey/lumen-oauth/internal/application/registration"
)

type RegisterHandler struct {
	Service registration.Service
}

func (h RegisterHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}
	err := h.Service.Register(r.Context(), registration.RegisterCommand{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
	})
	if err != nil {
		switch {
		case errors.Is(err, registration.ErrInvalidEmail):
			writeOAuthError(w, http.StatusBadRequest, "invalid_email", err.Error(), nil)
		case errors.Is(err, registration.ErrInvalidPassword):
			writeOAuthError(w, http.StatusBadRequest, "invalid_password", err.Error(), nil)
		case errors.Is(err, registration.ErrEmailAlreadyExists):
			writeOAuthError(w, http.StatusConflict, "email_exists", err.Error(), nil)
		case errors.Is(err, registration.ErrTooManyAttempts):
			writeOAuthError(w, http.StatusTooManyRequests, "too_many_attempts", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusInternalServerError, "internal_error", "registration failed", nil)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message": "verification code sent",
	})
}

func (h RegisterHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}
	err := h.Service.VerifyEmail(r.Context(), req.Email, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, registration.ErrInvalidCode):
			writeOAuthError(w, http.StatusBadRequest, "invalid_code", err.Error(), nil)
		case errors.Is(err, registration.ErrAlreadyVerified):
			writeOAuthError(w, http.StatusConflict, "already_verified", err.Error(), nil)
		case errors.Is(err, registration.ErrEmailAlreadyExists):
			writeOAuthError(w, http.StatusConflict, "email_exists", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusInternalServerError, "internal_error", "verification failed", nil)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"message": "email verified, you can now login",
	})
}
