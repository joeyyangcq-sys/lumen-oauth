package routes

import (
	"expvar"
	"net/http"

	"github.com/joey/lumen-oauth/internal/application/auth"
	"github.com/joey/lumen-oauth/internal/application/dcr"
	"github.com/joey/lumen-oauth/internal/application/invite"
	"github.com/joey/lumen-oauth/internal/application/rbac"
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
) http.Handler {
	o := handlers.OIDCHandler{Config: cfg, JWKSProvider: jwks.Provider{Issuer: cfg.OAuth.Issuer}}
	tokenHandler := handlers.TokenHandler{
		AuthService: authSvc,
	}
	dcrHandler := handlers.DCRHandler{Service: dcrSvc}
	inviteHandler := handlers.InviteHandler{Service: inviteSvc}
	adminHandler := handlers.AdminHandler{RBAC: rbacSvc}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handlers.Healthz)
	mux.HandleFunc("/.well-known/openid-configuration", o.Discovery)
	mux.HandleFunc("/.well-known/jwks.json", o.JWKS)
	mux.HandleFunc("/oauth/token", tokenHandler.Token)
	mux.HandleFunc("/connect/register", dcrHandler.RegisterClient)
	mux.HandleFunc("/auth/invitations", inviteHandler.CreateInvitation)
	mux.HandleFunc("/auth/register/accept", inviteHandler.AcceptInvitation)
	mux.HandleFunc("/admin/roles", methodSwitch(adminHandler.ListRoles, adminHandler.UpsertRole))
	mux.HandleFunc("/admin/role-bindings", adminHandler.BindRole)
	mux.Handle("/debug/vars", expvar.Handler())

	mws := []middleware.Middleware{
		middleware.RequestID,
		middleware.Recovery(log),
		middleware.AccessLog(log),
	}
	if cfg.Observability.MetricsEnabled {
		mws = append(mws, middleware.Metrics(metrics))
	}
	return middleware.Chain(mux, mws...)
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
