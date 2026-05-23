package routes

import (
	"expvar"
	"net/http"
	"net/http/pprof"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/auth"
	"github.com/joey/lumen-oauth/internal/application/dcr"
	"github.com/joey/lumen-oauth/internal/application/invite"
	"github.com/joey/lumen-oauth/internal/application/rbac"
	"github.com/joey/lumen-oauth/internal/application/registration"
	"github.com/joey/lumen-oauth/internal/config"
	"github.com/joey/lumen-oauth/internal/infrastructure/jwks"
	"github.com/joey/lumen-oauth/internal/interfaces/http/handlers"
	"github.com/joey/lumen-oauth/internal/interfaces/http/middleware"
	"github.com/joey/lumen-oauth/internal/platform/logging"
	"github.com/joey/lumen-oauth/internal/platform/observability"
)

func New(
	cfg config.Config,
	log *logging.Logger,
	metrics *observability.HTTPMetrics,
	authSvc auth.Service,
	dcrSvc dcr.Service,
	inviteSvc invite.Service,
	rbacSvc rbac.Service,
	regSvc *registration.Service,
) http.Handler {
	o := handlers.OIDCHandler{Config: cfg, JWKSProvider: jwks.Provider{Issuer: cfg.OAuth.Issuer, SigningKey: cfg.OAuth.SigningKey}}
	tokenHandler := handlers.TokenHandler{
		AuthService: authSvc,
	}
	authorizeHandler := handlers.AuthorizeHandler{
		AuthService: authSvc,
		Issuer:      cfg.OAuth.Issuer,
		AdminUIURL:  cfg.Server.AdminUIURL,
	}
	authHandler := handlers.AuthHandler{Service: authSvc}
	dcrHandler := handlers.DCRHandler{Service: dcrSvc}
	inviteHandler := handlers.InviteHandler{AuthService: authSvc, Service: inviteSvc}
	adminHandler := handlers.AdminHandler{AuthService: authSvc, RBAC: rbacSvc}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handlers.Healthz)
	mux.HandleFunc("/.well-known/oauth-authorization-server", o.OAuthAuthorizationServerMetadata)
	mux.HandleFunc("/.well-known/openid-configuration", o.Discovery)
	mux.HandleFunc("/.well-known/jwks.json", o.JWKS)
	mux.HandleFunc("/oauth/jwks.json", o.JWKS)
	mux.HandleFunc("/oauth/token", tokenHandler.Token)
	mux.HandleFunc("/oauth/authorize", authorizeHandler.Authorize)
	mux.HandleFunc("/oauth/consent", authorizeHandler.Consent)
	mux.HandleFunc("/oauth/consent/request", authorizeHandler.ConsentRequest)
	mux.HandleFunc("/oauth/register", dcrHandler.RegisterClient)
	mux.HandleFunc("/connect/register", dcrHandler.RegisterClient)
	mux.HandleFunc("/auth/login", authHandler.Login)
	mux.HandleFunc("/auth/logout", authHandler.Logout)
	mux.HandleFunc("/auth/me", authHandler.Me)
	mux.HandleFunc("/auth/invitations", inviteHandler.CreateInvitation)
	mux.HandleFunc("/auth/register/accept", inviteHandler.AcceptInvitation)
	if regSvc != nil {
		regHandler := handlers.RegisterHandler{Service: *regSvc}
		mux.HandleFunc("/auth/register", regHandler.Register)
		mux.HandleFunc("/auth/verify-email", regHandler.VerifyEmail)
	}
	mux.HandleFunc("/admin/roles", methodSwitch(adminHandler.ListRoles, adminHandler.UpsertRole))
	mux.HandleFunc("/admin/roles/delete", adminHandler.DeleteRole)
	mux.HandleFunc("/admin/role-bindings", adminHandler.BindRole)
	mux.HandleFunc("/admin/role-bindings/unbind", adminHandler.UnbindRole)
	if cfg.Observability.MetricsEnabled {
		metricsPath := cleanPath(cfg.Observability.MetricsPath, "/metrics")
		mux.Handle(metricsPath, expvar.Handler())
		if metricsPath != "/debug/vars" {
			mux.Handle("/debug/vars", expvar.Handler())
		}
	}
	if cfg.Observability.PProfEnabled {
		registerPProf(mux, cleanPath(cfg.Observability.PProfPath, "/debug/pprof"))
	}

	mws := []middleware.Middleware{
		middleware.SecurityHeaders,
		middleware.CORSWithOptions(middleware.CORSOptions{
			AllowedOrigins: cfg.Server.CORSAllowedOrigins,
		}),
		middleware.RequestID,
		middleware.Recovery(log),
		middleware.AccessLog(log),
	}
	if cfg.Observability.MetricsEnabled {
		mws = append(mws, middleware.Metrics(metrics))
	}
	return middleware.Chain(mux, mws...)
}

func cleanPath(path, fallback string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return fallback
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func registerPProf(mux *http.ServeMux, base string) {
	base = strings.TrimRight(base, "/")
	mux.HandleFunc(base+"/", pprof.Index)
	mux.HandleFunc(base+"/cmdline", pprof.Cmdline)
	mux.HandleFunc(base+"/profile", pprof.Profile)
	mux.HandleFunc(base+"/symbol", pprof.Symbol)
	mux.HandleFunc(base+"/trace", pprof.Trace)
	mux.Handle(base+"/allocs", pprof.Handler("allocs"))
	mux.Handle(base+"/block", pprof.Handler("block"))
	mux.Handle(base+"/goroutine", pprof.Handler("goroutine"))
	mux.Handle(base+"/heap", pprof.Handler("heap"))
	mux.Handle(base+"/mutex", pprof.Handler("mutex"))
	mux.Handle(base+"/threadcreate", pprof.Handler("threadcreate"))
}

func methodSwitch(getHandler, postHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getHandler(w, r)
		case http.MethodPost:
			postHandler(w, r)
		default:
			writeMethodNotAllowed(w)
		}
	}
}

func writeMethodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = w.Write([]byte(`{"code":"method_not_allowed","message":"unsupported method"}`))
}
