package middleware

import "net/http"

type CORSOptions struct {
	AllowedOrigins []string
}

var defaultCORSAllowedOrigins = []string{
	"http://127.0.0.1:5173",
	"http://localhost:5173",
}

func CORS(next http.Handler) http.Handler {
	return CORSWithOptions(CORSOptions{})(next)
}

func CORSWithOptions(opts CORSOptions) Middleware {
	allowedOrigins := map[string]struct{}{}
	origins := opts.AllowedOrigins
	if len(origins) == 0 {
		origins = defaultCORSAllowedOrigins
	}
	for _, origin := range origins {
		if origin != "" {
			allowedOrigins[origin] = struct{}{}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if _, ok := allowedOrigins[origin]; ok {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				addVary(w.Header(), "Origin")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, X-API-KEY, X-Request-Id, X-CSRF-Token")
			w.Header().Set("Access-Control-Expose-Headers", "X-Request-Id")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func addVary(header http.Header, value string) {
	for _, existing := range header.Values("Vary") {
		if existing == value {
			return
		}
	}
	header.Add("Vary", value)
}
