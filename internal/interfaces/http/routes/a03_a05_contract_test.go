package routes

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/joey/lumen-oauth/internal/application/auth"
	"github.com/joey/lumen-oauth/internal/application/dcr"
	inviteuc "github.com/joey/lumen-oauth/internal/application/invite"
	"github.com/joey/lumen-oauth/internal/application/rbac"
	"github.com/joey/lumen-oauth/internal/config"
	"github.com/joey/lumen-oauth/internal/infrastructure/clock"
	"github.com/joey/lumen-oauth/internal/infrastructure/idgen"
	"github.com/joey/lumen-oauth/internal/infrastructure/jwt"
	"github.com/joey/lumen-oauth/internal/infrastructure/sqlite"
	"github.com/joey/lumen-oauth/internal/platform/logging"
	"github.com/joey/lumen-oauth/internal/platform/observability"
)

func TestDCRIATInviteAndRBACContract(t *testing.T) {
	handler, cleanup := newTestHandler(t)
	defer cleanup()

	// A-03: DCR requires IAT (no IAT -> 401)
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewBufferString(`{"client_name":"bot","grant_types":["client_credentials"],"scope":"routes:read"}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("dcr no-iat status=%d, want 401", rec.Code)
		}
	}

	// A-03: valid IAT -> 201 + client credentials
	var dcrOut struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/connect/register", bytes.NewBufferString(`{"client_name":"bot","grant_types":["client_credentials"],"scope":"routes:read"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer local-dev-iat")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("dcr with iat status=%d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &dcrOut); err != nil {
			t.Fatalf("decode dcr response: %v", err)
		}
		if dcrOut.ClientID == "" || dcrOut.ClientSecret == "" {
			t.Fatalf("dcr response missing credentials: %+v", dcrOut)
		}
	}

	// A-05: before role binding, token request should be denied by scope policy.
	{
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", dcrOut.ClientID)
		form.Set("client_secret", dcrOut.ClientSecret)
		form.Set("scope", "routes:read")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("token before role bind status=%d, want 403, body=%s", rec.Code, rec.Body.String())
		}
	}

	// A-05: update role scopes + bind role to subject.
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/roles", bytes.NewBufferString(`{"role_name":"qa-role","scopes":["routes:read"]}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("upsert role status=%d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	}
	{
		payload := map[string]string{"subject": dcrOut.ClientID, "role_name": "qa-role"}
		raw, _ := json.Marshal(payload)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/role-bindings", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("bind role status=%d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	}

	// A-05 acceptance: same token request now succeeds.
	{
		form := url.Values{}
		form.Set("grant_type", "client_credentials")
		form.Set("client_id", dcrOut.ClientID)
		form.Set("client_secret", dcrOut.ClientSecret)
		form.Set("scope", "routes:read")
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewBufferString(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("token after role bind status=%d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	}

	// A-04: invite create + accept flow pass.
	var invitationCode string
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/invitations", bytes.NewBufferString(`{"email":"new.user@example.com","role":"qa-role"}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("create invite status=%d, want 201, body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		invitationCode, _ = body["code"].(string)
		if invitationCode == "" {
			t.Fatalf("missing invitation code in response: %v", body)
		}
	}
	{
		payload := map[string]string{"code": invitationCode, "subject": "new.user@example.com"}
		raw, _ := json.Marshal(payload)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/register/accept", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("accept invite status=%d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	}

	// RBAC minimal management: bind conflict on delete, then unbind and delete succeed.
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/roles", bytes.NewBufferString(`{"role_name":"qa-temp-role","scopes":["routes:read"]}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("upsert temp role status=%d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	}
	{
		payload := map[string]string{"subject": dcrOut.ClientID, "role_name": "qa-temp-role"}
		raw, _ := json.Marshal(payload)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/role-bindings", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("bind temp role status=%d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	}
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/roles/delete", bytes.NewBufferString(`{"role_name":"qa-temp-role"}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("delete bound role status=%d, want 400, body=%s", rec.Code, rec.Body.String())
		}
	}
	{
		payload := map[string]string{"subject": dcrOut.ClientID, "role_name": "qa-temp-role"}
		raw, _ := json.Marshal(payload)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/role-bindings/unbind", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("unbind role status=%d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	}
	{
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/admin/roles/delete", bytes.NewBufferString(`{"role_name":"qa-temp-role"}`))
		req.Header.Set("Content-Type", "application/json")
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("delete unbound role status=%d, want 200, body=%s", rec.Code, rec.Body.String())
		}
	}
}

func newTestHandler(t *testing.T) (http.Handler, func()) {
	t.Helper()
	cfg := config.Config{
		Server: config.ServerConfig{
			HTTPListen:   ":0",
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Logging: config.LoggingConfig{Level: "error", Format: "json"},
		Observability: config.ObservabilityConfig{
			MetricsEnabled: false,
			MetricsPath:    "/metrics",
		},
		OAuth: config.OAuthConfig{
			Issuer:         "http://127.0.0.1:9080",
			Audience:       []string{"lumen-mcp"},
			SigningKey:     "test-signing-key",
			AccessTokenTTL: 15 * time.Minute,
		},
		DCR: config.DCRConfig{
			IATRequired:         true,
			InitialAccessTokens: []string{"local-dev-iat"},
		},
		Invite:  config.InviteConfig{TTL: 24 * time.Hour},
		Storage: config.StorageConfig{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "oauth-test.db")},
	}

	repos, err := sqlite.OpenAndInit(cfg.Storage.SQLitePath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	authSvc := auth.Service{
		Clients:  repos,
		Roles:    repos,
		Signer:   jwt.Signer{SigningKey: cfg.OAuth.SigningKey},
		Clock:    clock.SystemClock{},
		IDGen:    idgen.RandomID{},
		Issuer:   cfg.OAuth.Issuer,
		Audience: cfg.OAuth.Audience,
		TTL:      cfg.OAuth.AccessTokenTTL,
	}
	dcrSvc := dcr.Service{
		Clients:             repos,
		IDGen:               idgen.RandomID{},
		IATRequired:         cfg.DCR.IATRequired,
		InitialAccessTokens: cfg.DCR.InitialAccessTokens,
	}
	rbacSvc := rbac.Service{Roles: repos}
	inviteSvc := inviteuc.Service{
		Invites:   repos,
		Roles:     repos,
		IDGen:     idgen.RandomID{},
		Clock:     clock.SystemClock{},
		InviteTTL: cfg.Invite.TTL,
	}

	h := New(cfg, logging.New("error", "json"), observability.NewHTTPMetrics(), authSvc, dcrSvc, inviteSvc, rbacSvc, nil)
	return h, func() { _ = repos.Close() }
}
