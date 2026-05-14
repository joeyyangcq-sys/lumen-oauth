package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSAllowsCredentialedConfiguredOrigins(t *testing.T) {
	h := CORSWithOptions(CORSOptions{
		AllowedOrigins: []string{"http://admin.example.test"},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/auth/logout", nil)
	req.Header.Set("Origin", "http://admin.example.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://admin.example.test" {
		t.Fatalf("allow-origin=%q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("allow-credentials=%q", rec.Header().Get("Access-Control-Allow-Credentials"))
	}
	if rec.Header().Get("Access-Control-Allow-Origin") == "*" {
		t.Fatalf("credentialed cors must not use wildcard origin")
	}
}

func TestCORSDoesNotReflectUnknownOrigins(t *testing.T) {
	h := CORSWithOptions(CORSOptions{
		AllowedOrigins: []string{"http://admin.example.test"},
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	req.Header.Set("Origin", "http://evil.example.test")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unexpected allow-origin=%q", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("unexpected allow-credentials=%q", rec.Header().Get("Access-Control-Allow-Credentials"))
	}
}
