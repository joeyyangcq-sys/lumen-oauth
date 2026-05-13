package middleware

import (
	"net/http"
	"time"

	"github.com/joey/lumen-oauth/internal/platform/observability"
)

func Metrics(m *observability.HTTPMetrics) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			m.Observe(rec.status, time.Since(start))
		})
	}
}
