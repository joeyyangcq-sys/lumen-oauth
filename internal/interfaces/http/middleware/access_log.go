package middleware

import (
	"net/http"
	"time"

	"github.com/joey/lumen-oauth/internal/platform/logging"
)

func AccessLog(log *logging.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := newResponseRecorder(w)
			next.ServeHTTP(rec, r)
			logRequest(log, r, rec, time.Since(start))
		})
	}
}

func logRequest(log *logging.Logger, r *http.Request, rec *responseRecorder, dur time.Duration) {
	args := []any{
		"method", r.Method,
		"route", routePattern(r),
		"path", r.URL.Path,
		"status", rec.status,
		"status_class", statusClass(rec.status),
		"duration_ms", dur.Milliseconds(),
		"bytes", rec.bytes,
		"request_id", TraceID(r.Context()),
	}
	if ua := r.UserAgent(); ua != "" {
		args = append(args, "user_agent", ua)
	}

	logger := log.WithContext(r.Context())
	switch {
	case rec.status >= http.StatusInternalServerError:
		logger.Error("http_request", args...)
	case rec.status >= http.StatusBadRequest:
		logger.Warn("http_request", args...)
	default:
		logger.Info("http_request", args...)
	}
}
