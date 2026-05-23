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
			rec := newResponseRecorder(w)
			next.ServeHTTP(rec, r)
			m.Observe(r.Method, routePattern(r), rec.status, time.Since(start))
		})
	}
}
