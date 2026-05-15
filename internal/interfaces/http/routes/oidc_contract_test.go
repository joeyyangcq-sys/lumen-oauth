package routes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/joey/lumen-oauth/internal/application/auth"
	"github.com/joey/lumen-oauth/internal/application/dcr"
	inviteuc "github.com/joey/lumen-oauth/internal/application/invite"
	"github.com/joey/lumen-oauth/internal/application/rbac"
	"github.com/joey/lumen-oauth/internal/config"
	"github.com/joey/lumen-oauth/internal/platform/logging"
)

func TestOIDCDiscoveryContract(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:9080")
	h := New(cfg, logging.New("error", "json"), nil, auth.Service{}, dcr.Service{}, inviteuc.Service{}, rbac.Service{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	assertStringField(t, body, "issuer", "http://127.0.0.1:9080")
	assertStringField(t, body, "jwks_uri", "http://127.0.0.1:9080/.well-known/jwks.json")
	assertStringField(t, body, "token_endpoint", "http://127.0.0.1:9080/oauth/token")
	assertStringField(t, body, "registration_endpoint", "http://127.0.0.1:9080/oauth/register")
	assertNonEmptyArray(t, body, "scopes_supported")
	assertNonEmptyArray(t, body, "grant_types_supported")
	assertNonEmptyArray(t, body, "response_types_supported")
	assertNonEmptyArray(t, body, "code_challenge_methods_supported")
}

func TestOAuthAuthorizationServerMetadataContract(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:9080")
	h := New(cfg, logging.New("error", "json"), nil, auth.Service{}, dcr.Service{}, inviteuc.Service{}, rbac.Service{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	assertStringField(t, body, "issuer", "http://127.0.0.1:9080")
	assertStringField(t, body, "authorization_endpoint", "http://127.0.0.1:9080/oauth/authorize")
	assertStringField(t, body, "token_endpoint", "http://127.0.0.1:9080/oauth/token")
	assertStringField(t, body, "registration_endpoint", "http://127.0.0.1:9080/oauth/register")
	assertStringField(t, body, "jwks_uri", "http://127.0.0.1:9080/oauth/jwks.json")
	assertNonEmptyArray(t, body, "code_challenge_methods_supported")
	assertNonEmptyArray(t, body, "token_endpoint_auth_methods_supported")
}

func TestJWKSContract(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:9080")
	h := New(cfg, logging.New("error", "json"), nil, auth.Service{}, dcr.Service{}, inviteuc.Service{}, rbac.Service{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	assertStringField(t, body, "issuer", "http://127.0.0.1:9080")
	keys, ok := body["keys"].([]any)
	if !ok {
		t.Fatalf("keys field has wrong type: %#v", body["keys"])
	}
	if keys == nil {
		t.Fatal("keys field should not be nil")
	}
}

func testConfig(issuer string) config.Config {
	return config.Config{
		Server: config.ServerConfig{
			HTTPListen:   ":9080",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
		Logging: config.LoggingConfig{
			Level:  "error",
			Format: "json",
		},
		Observability: config.ObservabilityConfig{
			MetricsEnabled: false,
			MetricsPath:    "/metrics",
		},
		OAuth: config.OAuthConfig{
			Issuer:         issuer,
			Audience:       []string{"lumen-mcp"},
			SigningKey:     "test-signing-key",
			AccessTokenTTL: 15 * time.Minute,
		},
	}
}

func assertStringField(t *testing.T, payload map[string]any, field, want string) {
	t.Helper()
	got, ok := payload[field].(string)
	if !ok {
		t.Fatalf("%s field has wrong type: %#v", field, payload[field])
	}
	if got != want {
		t.Fatalf("%s = %q, want %q", field, got, want)
	}
}

func assertNonEmptyArray(t *testing.T, payload map[string]any, field string) {
	t.Helper()
	values, ok := payload[field].([]any)
	if !ok {
		t.Fatalf("%s field has wrong type: %#v", field, payload[field])
	}
	if len(values) == 0 {
		t.Fatalf("%s should not be empty", field)
	}
}
