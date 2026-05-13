package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/dcr"
	"github.com/joey/lumen-oauth/internal/domain/client"
)

type DCRHandler struct {
	Service dcr.Service
}

func (h DCRHandler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}

	var req struct {
		ClientID   string   `json:"client_id"`
		ClientName string   `json:"client_name"`
		GrantTypes []string `json:"grant_types"`
		Scope      string   `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid json body", nil)
		return
	}

	bearer := strings.TrimSpace(r.Header.Get("Authorization"))
	out, err := h.Service.RegisterClient(r.Context(), bearer, client.OAuthClient{
		ID:         req.ClientID,
		Name:       req.ClientName,
		GrantTypes: req.GrantTypes,
		Scopes:     strings.Fields(req.Scope),
	})
	if err != nil {
		switch {
		case errors.Is(err, dcr.ErrUnauthorizedIAT):
			writeOAuthError(w, http.StatusUnauthorized, "unauthorized", err.Error(), nil)
		case errors.Is(err, dcr.ErrInvalidClient):
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusInternalServerError, "internal_error", err.Error(), nil)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(out)
}
