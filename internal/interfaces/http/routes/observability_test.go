package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestObservabilityRoutesUseConfiguredMetricsPath(t *testing.T) {
	handler, cleanup := newTestHandler(t, func(cfg *testHandlerConfig) {
		cfg.MetricsEnabled = true
		cfg.MetricsPath = "/internal/metrics"
	})
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/internal/metrics", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("configured metrics status=%d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("default metrics status=%d, want 404 when custom path is configured", rec.Code)
	}
}

func TestPProfRoutesRequireExplicitEnable(t *testing.T) {
	handler, cleanup := newTestHandler(t)
	defer cleanup()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled pprof status=%d, want 404", rec.Code)
	}

	handler, cleanup = newTestHandler(t, func(cfg *testHandlerConfig) {
		cfg.PProfEnabled = true
		cfg.PProfPath = "/internal/pprof"
	})
	defer cleanup()

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/internal/pprof/", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enabled pprof status=%d, want 200", rec.Code)
	}
}
