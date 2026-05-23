package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/joey/lumen-oauth/internal/application/auth"
	"github.com/joey/lumen-oauth/internal/application/dcr"
	inviteuc "github.com/joey/lumen-oauth/internal/application/invite"
	"github.com/joey/lumen-oauth/internal/application/rbac"
	"github.com/joey/lumen-oauth/internal/application/registration"
	"github.com/joey/lumen-oauth/internal/config"
	"github.com/joey/lumen-oauth/internal/infrastructure/clock"
	"github.com/joey/lumen-oauth/internal/infrastructure/email"
	"github.com/joey/lumen-oauth/internal/infrastructure/idgen"
	"github.com/joey/lumen-oauth/internal/infrastructure/jwt"
	"github.com/joey/lumen-oauth/internal/infrastructure/password"
	"github.com/joey/lumen-oauth/internal/infrastructure/redirect"
	"github.com/joey/lumen-oauth/internal/infrastructure/sqlite"
	"github.com/joey/lumen-oauth/internal/interfaces/http/routes"
	"github.com/joey/lumen-oauth/internal/platform/logging"
	"github.com/joey/lumen-oauth/internal/platform/observability"
)

type App struct {
	Config       config.Config
	Logger       *logging.Logger
	Metrics      *observability.HTTPMetrics
	Server       *http.Server
	Repositories sqlite.Repositories
}

func New(cfg config.Config) (*App, error) {
	log := logging.New(cfg.Logging.Level, cfg.Logging.Format)
	metrics := observability.NewHTTPMetrics()
	repos, err := openRepositories(cfg.Storage)
	if err != nil {
		return nil, err
	}
	passwordHasher := password.PBKDF2SHA256{}
	authSvc := auth.Service{
		Clients:    repos,
		Users:      repos,
		AuthCodes:  repos,
		Grants:     repos,
		Refreshes:  repos,
		Sessions:   repos,
		Roles:      repos,
		Signer:     jwt.Signer{SigningKey: cfg.OAuth.SigningKey},
		Verifier:   jwt.Verifier{SigningKey: cfg.OAuth.SigningKey},
		Passwords:  passwordHasher,
		Clock:      clock.SystemClock{},
		IDGen:      idgen.RandomID{},
		Issuer:     cfg.OAuth.Issuer,
		Audience:   cfg.OAuth.Audience,
		TTL:        maxDuration(cfg.OAuth.AccessTokenTTL, 15*time.Minute),
		CodeTTL:    maxDuration(cfg.OAuth.AuthorizationCodeTTL, 5*time.Minute),
		RefreshTTL: maxDuration(cfg.OAuth.RefreshTokenTTL, 30*24*time.Hour),
		SessionTTL: 12 * time.Hour,
	}
	if err := authSvc.EnsureBootstrapAdmin(context.Background(), auth.BootstrapAdminCommand{
		Enabled:             cfg.BootstrapAdmin.Enabled,
		Email:               cfg.BootstrapAdmin.Email,
		Password:            cfg.BootstrapAdmin.Password,
		Name:                cfg.BootstrapAdmin.Name,
		ForceChangePassword: cfg.BootstrapAdmin.ForceChangePassword,
	}); err != nil {
		_ = repos.Close()
		return nil, err
	}
	dcrSvc := dcr.Service{
		Clients: repos,
		Redirects: redirect.Validator{Config: redirect.Config{
			LoopbackEnabled: cfg.DCR.AllowedRedirects.LoopbackEnabled,
			LoopbackPaths:   cfg.DCR.AllowedRedirects.LoopbackPaths,
			CustomSchemes:   cfg.DCR.AllowedRedirects.CustomSchemes,
			HostedHTTPS:     cfg.DCR.AllowedRedirects.HostedHTTPS,
		}},
		IDGen:               idgen.RandomID{},
		Clock:               clock.SystemClock{},
		Enabled:             cfg.DCR.Enabled,
		Mode:                cfg.DCR.Mode,
		IATRequired:         cfg.DCR.IATRequired,
		InitialAccessTokens: cfg.DCR.InitialAccessTokens,
		SupportedScopes:     cfg.DCR.UnknownClientAllowedScopes,
		DefaultTrustLevel:   cfg.DCR.DefaultTrustLevel,
	}
	rbacSvc := rbac.Service{Roles: repos}
	inviteSvc := inviteuc.Service{
		Invites:   repos,
		Roles:     repos,
		IDGen:     idgen.RandomID{},
		Clock:     clock.SystemClock{},
		InviteTTL: cfg.Invite.TTL,
	}

	var regSvc *registration.Service
	if cfg.Registration.Enabled {
		var emailSender email.ConsoleSender
		svc := registration.Service{
			Users:         repos,
			Verifications: sqlite.VerificationAdapter{Repos: repos},
			Passwords:     passwordHasher,
			IDGen:         idgen.RandomID{},
			Clock:         clock.SystemClock{},
			DevMode:       cfg.SMTP.Host == "",
		}
		if cfg.SMTP.Host != "" {
			svc.Email = email.SMTPSender{
				Host:     cfg.SMTP.Host,
				Port:     cfg.SMTP.Port,
				Username: cfg.SMTP.Username,
				Password: cfg.SMTP.Password,
				From:     cfg.SMTP.From,
			}
		} else {
			svc.Email = emailSender
		}
		regSvc = &svc
	}

	handler := routes.New(cfg, log, metrics, authSvc, dcrSvc, inviteSvc, rbacSvc, regSvc)
	return &App{
		Config:       cfg,
		Logger:       log,
		Metrics:      metrics,
		Repositories: repos,
		Server: &http.Server{
			Addr:         cfg.Server.HTTPListen,
			Handler:      handler,
			ReadTimeout:  cfg.Server.ReadTimeout,
			WriteTimeout: cfg.Server.WriteTimeout,
		},
	}, nil
}

func openRepositories(cfg config.StorageConfig) (sqlite.Repositories, error) {
	switch cfg.Driver {
	case "postgres":
		return sqlite.OpenPostgresAndInit(cfg.PostgresURL)
	case "sqlite":
		return sqlite.OpenAndInit(cfg.SQLitePath)
	default:
		return sqlite.Repositories{}, fmt.Errorf("unsupported storage.driver: %q", cfg.Driver)
	}
}

func (a *App) Run(ctx context.Context) error {
	defer func() {
		if err := a.Repositories.Close(); err != nil {
			a.Logger.Error("close repositories failed", "error", err)
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		a.Logger.Info("oauth server starting", "listen", a.Config.Server.HTTPListen)
		errCh <- a.Server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		a.Logger.Info("oauth server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func maxDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}
