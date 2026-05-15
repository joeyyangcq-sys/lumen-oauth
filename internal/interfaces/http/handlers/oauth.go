package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
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
	switch grantType {
	case "client_credentials":
		h.clientCredentials(w, r)
	case "authorization_code":
		h.authorizationCode(w, r)
	case "refresh_token":
		h.refreshToken(w, r)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type", nil)
		return
	}
}

func (h TokenHandler) clientCredentials(w http.ResponseWriter, r *http.Request) {
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

func (h TokenHandler) authorizationCode(w http.ResponseWriter, r *http.Request) {
	issued, err := h.AuthService.ExchangeAuthorizationCode(r.Context(), auth.AuthorizationCodeTokenCommand{
		Code:         strings.TrimSpace(r.FormValue("code")),
		ClientID:     strings.TrimSpace(r.FormValue("client_id")),
		ClientSecret: strings.TrimSpace(r.FormValue("client_secret")),
		RedirectURI:  strings.TrimSpace(r.FormValue("redirect_uri")),
		CodeVerifier: strings.TrimSpace(r.FormValue("code_verifier")),
		Resource:     strings.TrimSpace(r.FormValue("resource")),
	})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrPKCEVerificationFailed):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error(), nil)
		case errors.Is(err, auth.ErrInvalidClientCredentials):
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error(), nil)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  issued.AccessToken.Value,
		"token_type":    "Bearer",
		"expires_in":    int(issued.AccessToken.ExpiresAt.Sub(issued.AccessToken.IssuedAt).Seconds()),
		"scope":         strings.Join(issued.AccessToken.Scopes, " "),
		"refresh_token": issued.RefreshToken,
	})
}

func (h TokenHandler) refreshToken(w http.ResponseWriter, r *http.Request) {
	issued, err := h.AuthService.Refresh(r.Context(), auth.RefreshTokenCommand{
		RefreshToken: strings.TrimSpace(r.FormValue("refresh_token")),
		ClientID:     strings.TrimSpace(r.FormValue("client_id")),
		Resource:     strings.TrimSpace(r.FormValue("resource")),
	})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrRefreshTokenReuse):
			writeOAuthError(w, http.StatusUnauthorized, "invalid_grant", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error(), nil)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  issued.AccessToken.Value,
		"token_type":    "Bearer",
		"expires_in":    int(issued.AccessToken.ExpiresAt.Sub(issued.AccessToken.IssuedAt).Seconds()),
		"scope":         strings.Join(issued.AccessToken.Scopes, " "),
		"refresh_token": issued.RefreshToken,
	})
}

type AuthorizeHandler struct {
	AuthService auth.Service
	Issuer      string
	AdminUIURL  string
}

func (h AuthorizeHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required", nil)
		return
	}
	q := r.URL.Query()
	sessionID := ""
	if cookie, err := r.Cookie("lumen_session"); err == nil {
		sessionID = cookie.Value
	}
	out, err := h.AuthService.Authorize(r.Context(), auth.AuthorizeCommand{
		Bearer:              r.Header.Get("Authorization"),
		SessionID:           sessionID,
		ResponseType:        strings.TrimSpace(q.Get("response_type")),
		ClientID:            strings.TrimSpace(q.Get("client_id")),
		RedirectURI:         strings.TrimSpace(q.Get("redirect_uri")),
		Scope:               strings.Fields(q.Get("scope")),
		State:               q.Get("state"),
		CodeChallenge:       strings.TrimSpace(q.Get("code_challenge")),
		CodeChallengeMethod: strings.TrimSpace(q.Get("code_challenge_method")),
		Resource:            strings.TrimSpace(q.Get("resource")),
	})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUnauthorized):
			returnTo := h.Issuer + r.URL.RequestURI()
			loginURL := strings.TrimRight(h.AdminUIURL, "/") + "/login?return_to=" + url.QueryEscape(returnTo)
			http.Redirect(w, r, loginURL, http.StatusFound)
		case errors.Is(err, auth.ErrConsentRequired):
			consentURL := strings.TrimRight(h.AdminUIURL, "/") + "/oauth/consent?" + url.Values{
				"issuer":                {h.Issuer},
				"client_id":             {q.Get("client_id")},
				"redirect_uri":          {q.Get("redirect_uri")},
				"scope":                 {q.Get("scope")},
				"state":                 {q.Get("state")},
				"resource":              {q.Get("resource")},
				"code_challenge":        {q.Get("code_challenge")},
				"code_challenge_method": {q.Get("code_challenge_method")},
			}.Encode()
			http.Redirect(w, r, consentURL, http.StatusFound)
		case errors.Is(err, auth.ErrNoScopeGranted):
			writeOAuthError(w, http.StatusForbidden, "invalid_scope", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		}
		return
	}
	redirectURL, err := url.Parse(out.RedirectURI)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid redirect_uri", nil)
		return
	}
	values := redirectURL.Query()
	values.Set("code", out.Code)
	if out.State != "" {
		values.Set("state", out.State)
	}
	redirectURL.RawQuery = values.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (h AuthorizeHandler) Consent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST required", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "failed to parse form", nil)
		return
	}
	sessionID := ""
	if cookie, err := r.Cookie("lumen_session"); err == nil {
		sessionID = cookie.Value
	}
	if strings.TrimSpace(sessionID) == "" {
		writeOAuthError(w, http.StatusUnauthorized, "login_required", "missing session", nil)
		return
	}
	if err := h.AuthService.ValidateCSRF(r.Context(), sessionID, r.Header.Get("X-CSRF-Token")); err != nil {
		writeOAuthError(w, http.StatusForbidden, "csrf_required", "invalid csrf token", nil)
		return
	}
	if err := h.AuthService.Consent(r.Context(), auth.AuthorizeCommand{
		SessionID:   sessionID,
		ClientID:    strings.TrimSpace(r.FormValue("client_id")),
		RedirectURI: strings.TrimSpace(r.FormValue("redirect_uri")),
		Scope:       strings.Fields(r.FormValue("scope")),
		Resource:    strings.TrimSpace(r.FormValue("resource")),
	}); err != nil {
		switch {
		case errors.Is(err, auth.ErrUnauthorized):
			writeOAuthError(w, http.StatusUnauthorized, "login_required", err.Error(), nil)
		case errors.Is(err, auth.ErrNoScopeGranted):
			writeOAuthError(w, http.StatusForbidden, "invalid_scope", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

func (h AuthorizeHandler) ConsentRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeOAuthError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET required", nil)
		return
	}
	q := r.URL.Query()
	sessionID := ""
	if cookie, err := r.Cookie("lumen_session"); err == nil {
		sessionID = cookie.Value
	}
	if strings.TrimSpace(sessionID) == "" {
		writeOAuthError(w, http.StatusUnauthorized, "login_required", "missing session", nil)
		return
	}
	out, err := h.AuthService.ConsentRequest(r.Context(), auth.AuthorizeCommand{
		SessionID:   sessionID,
		ClientID:    strings.TrimSpace(q.Get("client_id")),
		RedirectURI: strings.TrimSpace(q.Get("redirect_uri")),
		Scope:       strings.Fields(q.Get("scope")),
		Resource:    strings.TrimSpace(q.Get("resource")),
	})
	if err != nil {
		switch {
		case errors.Is(err, auth.ErrUnauthorized):
			writeOAuthError(w, http.StatusUnauthorized, "login_required", err.Error(), nil)
		case errors.Is(err, auth.ErrNoScopeGranted):
			writeOAuthError(w, http.StatusForbidden, "invalid_scope", err.Error(), nil)
		default:
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
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
