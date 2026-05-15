package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/rbac"
)

type AdminHandler struct {
	RBAC rbac.Service
}

func (h AdminHandler) ListRoles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required", nil)
		return
	}
	roles, err := h.RBAC.ListRoles(r.Context())
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"list": roles, "total": len(roles)})
}

func (h AdminHandler) UpsertRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	var req struct {
		RoleName string   `json:"role_name"`
		Scopes   []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}
	if err := h.RBAC.UpsertRoleScopes(r.Context(), req.RoleName, req.Scopes); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (h AdminHandler) BindRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	var req struct {
		Subject  string `json:"subject"`
		RoleName string `json:"role_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	req.RoleName = strings.TrimSpace(req.RoleName)
	if req.Subject == "" || req.RoleName == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "subject and role_name are required", nil)
		return
	}
	if err := h.RBAC.BindRoleToSubject(r.Context(), req.Subject, req.RoleName); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (h AdminHandler) UnbindRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	var req struct {
		Subject  string `json:"subject"`
		RoleName string `json:"role_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	req.RoleName = strings.TrimSpace(req.RoleName)
	if req.Subject == "" || req.RoleName == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "subject and role_name are required", nil)
		return
	}
	if err := h.RBAC.UnbindRoleFromSubject(r.Context(), req.Subject, req.RoleName); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (h AdminHandler) DeleteRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	var req struct {
		RoleName string `json:"role_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}
	req.RoleName = strings.TrimSpace(req.RoleName)
	if req.RoleName == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "role_name is required", nil)
		return
	}
	if err := h.RBAC.DeleteRole(r.Context(), req.RoleName); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}
