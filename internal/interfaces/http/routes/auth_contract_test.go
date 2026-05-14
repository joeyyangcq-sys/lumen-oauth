package routes

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/joey/lumen-oauth/internal/application/auth"
	"github.com/joey/lumen-oauth/internal/application/dcr"
	inviteuc "github.com/joey/lumen-oauth/internal/application/invite"
	"github.com/joey/lumen-oauth/internal/application/rbac"
	"github.com/joey/lumen-oauth/internal/config"
	"github.com/joey/lumen-oauth/internal/domain/client"
	"github.com/joey/lumen-oauth/internal/infrastructure/clock"
	"github.com/joey/lumen-oauth/internal/infrastructure/idgen"
	"github.com/joey/lumen-oauth/internal/infrastructure/jwt"
	"github.com/joey/lumen-oauth/internal/infrastructure/password"
	"github.com/joey/lumen-oauth/internal/infrastructure/sqlite"
	"github.com/joey/lumen-oauth/internal/platform/logging"
)

func TestAuthLoginAndMeContract(t *testing.T) {
	cfg := config.Config{
		Server: config.ServerConfig{
			HTTPListen:   ":0",
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Logging:       config.LoggingConfig{Level: "error", Format: "json"},
		Observability: config.ObservabilityConfig{MetricsEnabled: false, MetricsPath: "/metrics"},
		OAuth: config.OAuthConfig{
			Issuer:         "http://127.0.0.1:9080",
			Audience:       []string{"lumen-admin-ui", "https://mcp.example.com/mcp"},
			SigningKey:     "test-signing-key",
			AccessTokenTTL: 15 * time.Minute,
		},
		Storage: config.StorageConfig{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "oauth-auth-test.db")},
	}
	repos, err := sqlite.OpenAndInit(cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer repos.Close()

	hasher := password.PBKDF2SHA256{}
	authSvc := auth.Service{
		Clients:   repos,
		Users:     repos,
		AuthCodes: repos,
		Grants:    repos,
		Refreshes: repos,
		Sessions:  repos,
		Roles:     repos,
		Signer:    jwt.Signer{SigningKey: cfg.OAuth.SigningKey},
		Verifier:  jwt.Verifier{SigningKey: cfg.OAuth.SigningKey},
		Passwords: hasher,
		Clock:     clock.SystemClock{},
		IDGen:     idgen.RandomID{},
		Issuer:    cfg.OAuth.Issuer,
		Audience:  cfg.OAuth.Audience,
		TTL:       cfg.OAuth.AccessTokenTTL,
	}
	if err := authSvc.EnsureBootstrapAdmin(t.Context(), auth.BootstrapAdminCommand{
		Enabled:             true,
		Email:               "admin@example.com",
		Password:            "admin",
		Name:                "Default Admin",
		ForceChangePassword: true,
	}); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}

	h := New(cfg, logging.New("error", "json"), nil, authSvc, dcr.Service{}, inviteuc.Service{}, rbac.Service{})
	preflightReq := httptest.NewRequest(http.MethodOptions, "/auth/logout", nil)
	preflightReq.Header.Set("Origin", "http://127.0.0.1:5173")
	preflightReq.Header.Set("Access-Control-Request-Method", "POST")
	preflightReq.Header.Set("Access-Control-Request-Headers", "Content-Type, X-CSRF-Token")
	preflightRec := httptest.NewRecorder()
	h.ServeHTTP(preflightRec, preflightReq)
	if preflightRec.Code != http.StatusNoContent {
		t.Fatalf("preflight status=%d body=%s", preflightRec.Code, preflightRec.Body.String())
	}
	if preflightRec.Header().Get("Access-Control-Allow-Origin") != "http://127.0.0.1:5173" {
		t.Fatalf("preflight allow-origin=%q", preflightRec.Header().Get("Access-Control-Allow-Origin"))
	}
	if preflightRec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("preflight allow-credentials=%q", preflightRec.Header().Get("Access-Control-Allow-Credentials"))
	}
	if !strings.Contains(preflightRec.Header().Get("Access-Control-Allow-Headers"), "X-CSRF-Token") {
		t.Fatalf("preflight allow-headers missing csrf: %q", preflightRec.Header().Get("Access-Control-Allow-Headers"))
	}

	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"email":"admin@example.com","password":"admin"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	var loginBody struct {
		AccessToken string `json:"access_token"`
		CSRFToken   string `json:"csrf_token"`
		User        struct {
			IsAdmin bool `json:"is_admin"`
		} `json:"user"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginBody); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginBody.AccessToken == "" || loginBody.CSRFToken == "" || !loginBody.User.IsAdmin {
		t.Fatalf("unexpected login response: %+v", loginBody)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range loginRec.Result().Cookies() {
		if cookie.Name == "lumen_session" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" || !sessionCookie.HttpOnly {
		t.Fatalf("missing HttpOnly lumen_session cookie: %#v", loginRec.Result().Cookies())
	}

	meReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+loginBody.AccessToken)
	meRec := httptest.NewRecorder()
	h.ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusOK {
		t.Fatalf("me status=%d body=%s", meRec.Code, meRec.Body.String())
	}
	var meBody struct {
		Email   string `json:"email"`
		IsAdmin bool   `json:"is_admin"`
	}
	if err := json.Unmarshal(meRec.Body.Bytes(), &meBody); err != nil {
		t.Fatalf("decode me response: %v", err)
	}
	if meBody.Email != "admin@example.com" || !meBody.IsAdmin {
		t.Fatalf("unexpected me response: %+v", meBody)
	}

	if err := repos.Save(t.Context(), client.OAuthClient{
		ID:                      "mcp-client",
		Name:                    "MCP Client",
		RedirectURIs:            []string{"http://localhost:3118/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scopes:                  []string{"mcp:tools", "offline_access"},
		TrustLevel:              "known_public",
	}); err != nil {
		t.Fatalf("save client: %v", err)
	}

	verifier := "test-code-verifier"
	challenge := pkceChallenge(verifier)
	authURL := "/oauth/authorize?response_type=code&client_id=mcp-client&redirect_uri=" +
		url.QueryEscape("http://localhost:3118/callback") +
		"&scope=" + url.QueryEscape("mcp:tools offline_access") +
		"&state=state-1&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256&resource=" + url.QueryEscape("https://mcp.example.com/mcp")
	authReq := httptest.NewRequest(http.MethodGet, authURL, nil)
	authReq.AddCookie(sessionCookie)
	authRec := httptest.NewRecorder()
	h.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusForbidden {
		t.Fatalf("authorize before consent status=%d want 403 body=%s", authRec.Code, authRec.Body.String())
	}

	consentRequestURL := "/oauth/consent/request?client_id=mcp-client&redirect_uri=" +
		url.QueryEscape("http://localhost:3118/callback") +
		"&scope=" + url.QueryEscape("mcp:tools offline_access") +
		"&resource=" + url.QueryEscape("https://mcp.example.com/mcp")
	consentViewReq := httptest.NewRequest(http.MethodGet, consentRequestURL, nil)
	consentViewReq.AddCookie(sessionCookie)
	consentViewRec := httptest.NewRecorder()
	h.ServeHTTP(consentViewRec, consentViewReq)
	if consentViewRec.Code != http.StatusOK {
		t.Fatalf("consent request status=%d body=%s", consentViewRec.Code, consentViewRec.Body.String())
	}
	var consentView struct {
		ClientID        string `json:"client_id"`
		RedirectHost    string `json:"redirect_host"`
		ConsentRequired bool   `json:"consent_required"`
		Scopes          []struct {
			Value string `json:"value"`
		} `json:"scopes"`
	}
	if err := json.Unmarshal(consentViewRec.Body.Bytes(), &consentView); err != nil {
		t.Fatalf("decode consent request: %v", err)
	}
	if consentView.ClientID != "mcp-client" || consentView.RedirectHost != "localhost:3118" || !consentView.ConsentRequired || len(consentView.Scopes) != 2 {
		t.Fatalf("unexpected consent request: %+v", consentView)
	}

	consentForm := url.Values{}
	consentForm.Set("client_id", "mcp-client")
	consentForm.Set("redirect_uri", "http://localhost:3118/callback")
	consentForm.Set("scope", "mcp:tools offline_access")
	consentForm.Set("resource", "https://mcp.example.com/mcp")
	missingCSRFReq := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(consentForm.Encode()))
	missingCSRFReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	missingCSRFReq.AddCookie(sessionCookie)
	missingCSRFRec := httptest.NewRecorder()
	h.ServeHTTP(missingCSRFRec, missingCSRFReq)
	if missingCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("consent without csrf status=%d want 403 body=%s", missingCSRFRec.Code, missingCSRFRec.Body.String())
	}

	consentReq := httptest.NewRequest(http.MethodPost, "/oauth/consent", strings.NewReader(consentForm.Encode()))
	consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	consentReq.AddCookie(sessionCookie)
	consentReq.Header.Set("X-CSRF-Token", loginBody.CSRFToken)
	consentRec := httptest.NewRecorder()
	h.ServeHTTP(consentRec, consentReq)
	if consentRec.Code != http.StatusOK {
		t.Fatalf("consent status=%d body=%s", consentRec.Code, consentRec.Body.String())
	}

	authReq = httptest.NewRequest(http.MethodGet, authURL, nil)
	authReq.AddCookie(sessionCookie)
	authRec = httptest.NewRecorder()
	h.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("authorize status=%d body=%s", authRec.Code, authRec.Body.String())
	}
	location := authRec.Header().Get("Location")
	redirected, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	code := redirected.Query().Get("code")
	if code == "" || redirected.Query().Get("state") != "state-1" {
		t.Fatalf("unexpected redirect location: %s", location)
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "mcp-client")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost:3118/callback")
	form.Set("code_verifier", verifier)
	form.Set("resource", "https://mcp.example.com/mcp")
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.ServeHTTP(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokenBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokenBody); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenBody.AccessToken == "" || tokenBody.RefreshToken == "" || tokenBody.Scope != "mcp:tools offline_access" {
		t.Fatalf("unexpected token response: %+v", tokenBody)
	}

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("client_id", "mcp-client")
	refreshForm.Set("refresh_token", tokenBody.RefreshToken)
	refreshForm.Set("resource", "https://mcp.example.com/mcp")
	refreshReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.ServeHTTP(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status=%d body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshBody struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(refreshRec.Body.Bytes(), &refreshBody); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if refreshBody.AccessToken == "" || refreshBody.RefreshToken == "" || refreshBody.RefreshToken == tokenBody.RefreshToken {
		t.Fatalf("unexpected refresh response: %+v", refreshBody)
	}

	reuseReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	reuseReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reuseRec := httptest.NewRecorder()
	h.ServeHTTP(reuseRec, reuseReq)
	if reuseRec.Code != http.StatusUnauthorized {
		t.Fatalf("reuse status=%d want 401 body=%s", reuseRec.Code, reuseRec.Body.String())
	}

	badLogoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	badLogoutReq.AddCookie(sessionCookie)
	badLogoutRec := httptest.NewRecorder()
	h.ServeHTTP(badLogoutRec, badLogoutReq)
	if badLogoutRec.Code != http.StatusForbidden {
		t.Fatalf("logout without csrf status=%d want 403 body=%s", badLogoutRec.Code, badLogoutRec.Body.String())
	}

	logoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	logoutReq.AddCookie(sessionCookie)
	logoutReq.Header.Set("Origin", "http://127.0.0.1:5173")
	logoutReq.Header.Set("X-CSRF-Token", loginBody.CSRFToken)
	logoutRec := httptest.NewRecorder()
	h.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("logout status=%d body=%s", logoutRec.Code, logoutRec.Body.String())
	}
	if logoutRec.Header().Get("Content-Security-Policy") == "" || logoutRec.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("missing security headers: %#v", logoutRec.Header())
	}
	if logoutRec.Header().Get("Access-Control-Allow-Origin") != "http://127.0.0.1:5173" {
		t.Fatalf("logout allow-origin=%q", logoutRec.Header().Get("Access-Control-Allow-Origin"))
	}
	if logoutRec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("logout allow-credentials=%q", logoutRec.Header().Get("Access-Control-Allow-Credentials"))
	}
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
