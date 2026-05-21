package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/joey/lumen-oauth/internal/platform/logging"
)

func TestRequestIDStoresTypedTraceID(t *testing.T) {
	var gotRequestID string
	var gotTraceID string
	h := RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotRequestID = TraceID(r.Context())
		gotTraceID = logging.TraceID(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", "req-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if gotRequestID != "req-123" {
		t.Fatalf("request id=%q, want req-123", gotRequestID)
	}
	if gotTraceID != "req-123" {
		t.Fatalf("trace id=%q, want req-123", gotTraceID)
	}
	if rec.Header().Get("X-Request-Id") != "req-123" {
		t.Fatalf("response header=%q, want req-123", rec.Header().Get("X-Request-Id"))
	}
}
