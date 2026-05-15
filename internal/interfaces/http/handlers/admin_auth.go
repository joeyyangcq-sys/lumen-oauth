package handlers

import (
	"net/http"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/auth"
)

func requireAdmin(w http.ResponseWriter, r *http.Request, authService auth.Service) (auth.UserSession, bool) {
	bearer := strings.TrimSpace(r.Header.Get("Authorization"))
	if bearer == "" {
		writeOAuthError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token", nil)
		return auth.UserSession{}, false
	}

	userSession, err := authService.Me(r.Context(), bearer)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "unauthorized", "invalid bearer token", nil)
		return auth.UserSession{}, false
	}
	if !userSession.IsAdmin {
		writeOAuthError(w, http.StatusForbidden, "forbidden", "admin privileges required", nil)
		return auth.UserSession{}, false
	}

	return userSession, true
}
