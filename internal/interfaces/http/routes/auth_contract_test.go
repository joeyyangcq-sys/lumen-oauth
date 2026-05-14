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
	loginReq := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"email":"admin@example.com","password":"admin"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRec := httptest.NewRecorder()
	h.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginRec.Code, loginRec.Body.String())
	}
	var loginBody struct {
		AccessToken string `json:"access_token"`
		User        struct {
			IsAdmin bool `json:"is_admin"`
		} `json:"user"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginBody); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginBody.AccessToken == "" || !loginBody.User.IsAdmin {
		t.Fatalf("unexpected login response: %+v", loginBody)
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
	authReq.Header.Set("Authorization", "Bearer "+loginBody.AccessToken)
	authRec := httptest.NewRecorder()
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
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
