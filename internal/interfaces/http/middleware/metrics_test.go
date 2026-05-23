package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/joey/lumen-oauth/internal/platform/observability"
)

func TestMetricsUsesRoutePatternAndStatusClass(t *testing.T) {
	metrics := observability.NewHTTPMetrics()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	handler := Metrics(metrics)(mux)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	snapshot := metrics.RouteSnapshot()
	if len(snapshot) != 1 {
		t.Fatalf("route metrics len=%d, want 1: %+v", len(snapshot), snapshot)
	}
	if snapshot[0].Method != http.MethodGet {
		t.Fatalf("method=%q, want GET", snapshot[0].Method)
	}
	if snapshot[0].Route != "/healthz" {
		t.Fatalf("route=%q, want /healthz", snapshot[0].Route)
	}
	if snapshot[0].StatusClass != "2xx" {
		t.Fatalf("status_class=%q, want 2xx", snapshot[0].StatusClass)
	}
	if snapshot[0].Requests != 1 || snapshot[0].Errors != 0 {
		t.Fatalf("unexpected counts: %+v", snapshot[0])
	}
}

func TestMetricsUsesUnmatchedForUnknownRoutes(t *testing.T) {
	metrics := observability.NewHTTPMetrics()
	handler := Metrics(metrics)(http.NewServeMux())

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/users/12345/private", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	snapshot := metrics.RouteSnapshot()
	if len(snapshot) != 1 {
		t.Fatalf("route metrics len=%d, want 1: %+v", len(snapshot), snapshot)
	}
	if snapshot[0].Route != "unmatched" {
		t.Fatalf("route=%q, want unmatched", snapshot[0].Route)
	}
	if snapshot[0].StatusClass != "4xx" || snapshot[0].Errors != 1 {
		t.Fatalf("unexpected error metrics: %+v", snapshot[0])
	}
}
