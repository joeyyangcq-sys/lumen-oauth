package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/joey/lumen-oauth/internal/platform/logging"
)

func Recovery(log *logging.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.WithContext(r.Context()).Error("panic recovered", "panic", rec, "stack", string(debug.Stack()))
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
