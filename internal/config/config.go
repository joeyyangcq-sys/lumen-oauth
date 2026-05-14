package config

import (
	"errors"
	"fmt"
	"time"
)

type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Logging        LoggingConfig        `yaml:"logging"`
	Observability  ObservabilityConfig  `yaml:"observability"`
	OAuth          OAuthConfig          `yaml:"oauth"`
	Auth           AuthConfig           `yaml:"auth"`
	BootstrapAdmin BootstrapAdminConfig `yaml:"bootstrap_admin"`
	DCR            DCRConfig            `yaml:"dcr"`
	Invite         InviteConfig         `yaml:"invite"`
	Storage        StorageConfig        `yaml:"storage"`
}

type ServerConfig struct {
	HTTPListen         string        `yaml:"http_listen"`
	ReadTimeout        time.Duration `yaml:"read_timeout"`
	WriteTimeout       time.Duration `yaml:"write_timeout"`
	CORSAllowedOrigins []string      `yaml:"cors_allowed_origins"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type ObservabilityConfig struct {
	MetricsEnabled bool   `yaml:"metrics_enabled"`
	MetricsPath    string `yaml:"metrics_path"`
}

type OAuthConfig struct {
	Issuer               string        `yaml:"issuer"`
	Audience             []string      `yaml:"audience"`
	SigningKey           string        `yaml:"signing_key"`
	AccessTokenTTL       time.Duration `yaml:"access_token_ttl"`
	RefreshTokenTTL      time.Duration `yaml:"refresh_token_ttl"`
	AuthorizationCodeTTL time.Duration `yaml:"authorization_code_ttl"`
	SupportedScopes      []string      `yaml:"supported_scopes"`
}

type DCRConfig struct {
	Enabled                    bool                  `yaml:"enabled"`
	Mode                       string                `yaml:"mode"`
	IATRequired                bool                  `yaml:"iat_required"`
	InitialAccessTokens        []string              `yaml:"initial_access_tokens"`
	DefaultTrustLevel          string                `yaml:"default_trust_level"`
	UnknownClientAllowedScopes []string              `yaml:"unknown_client_allowed_scopes"`
	AllowedRedirects           AllowedRedirectConfig `yaml:"allowed_redirects"`
}

type AuthConfig struct {
	PasswordHash PasswordHashConfig `yaml:"password_hash"`
}

type PasswordHashConfig struct {
	Algorithm string `yaml:"algorithm"`
}

type BootstrapAdminConfig struct {
	Enabled             bool   `yaml:"enabled"`
	Email               string `yaml:"email"`
	Password            string `yaml:"password"`
	Name                string `yaml:"name"`
	ForceChangePassword bool   `yaml:"force_change_password"`
}

type AllowedRedirectConfig struct {
	LoopbackEnabled bool     `yaml:"loopback_enabled"`
	LoopbackPaths   []string `yaml:"loopback_paths"`
	CustomSchemes   []string `yaml:"custom_schemes"`
	HostedHTTPS     []string `yaml:"hosted_https"`
}

type InviteConfig struct {
	TTL time.Duration `yaml:"ttl"`
}

type StorageConfig struct {
	Driver      string `yaml:"driver"`
	SQLitePath  string `yaml:"sqlite_path"`
	PostgresURL string `yaml:"postgres_url"`
}

func (c *Config) ApplyDefaults() {
	if c.Server.HTTPListen == "" {
		c.Server.HTTPListen = ":9080"
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 10 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 10 * time.Second
	}
	if len(c.Server.CORSAllowedOrigins) == 0 {
		c.Server.CORSAllowedOrigins = []string{"http://127.0.0.1:5173", "http://localhost:5173"}
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Observability.MetricsPath == "" {
		c.Observability.MetricsPath = "/metrics"
	}
	if c.Auth.PasswordHash.Algorithm == "" {
		c.Auth.PasswordHash.Algorithm = "pbkdf2-sha256"
	}
	if c.BootstrapAdmin.Email == "" {
		c.BootstrapAdmin.Email = "admin@example.com"
	}
	if c.BootstrapAdmin.Password == "" {
		c.BootstrapAdmin.Password = "admin"
	}
	if c.BootstrapAdmin.Name == "" {
		c.BootstrapAdmin.Name = "Default Admin"
	}
	if c.OAuth.AccessTokenTTL == 0 {
		c.OAuth.AccessTokenTTL = 15 * time.Minute
	}
	if c.OAuth.RefreshTokenTTL == 0 {
		c.OAuth.RefreshTokenTTL = 30 * 24 * time.Hour
	}
	if c.OAuth.AuthorizationCodeTTL == 0 {
		c.OAuth.AuthorizationCodeTTL = 5 * time.Minute
	}
	if len(c.OAuth.SupportedScopes) == 0 {
		c.OAuth.SupportedScopes = []string{
			"openid", "profile", "email",
			"mcp:tools", "mcp:read", "mcp:write",
			"offline_access",
			"routes:read", "routes:write",
			"services:read", "services:write",
			"upstreams:read", "upstreams:write",
			"plugins:read", "plugins:write",
			"global_rules:read", "global_rules:write",
			"gateway:read", "gateway:write", "gateway:dangerous",
			"oauth:read", "oauth:write",
			"admin", "admin:dangerous",
		}
	}
	if c.DCR.Mode == "" {
		if c.DCR.IATRequired {
			c.DCR.Mode = "iat_required"
		} else {
			c.DCR.Mode = "guarded"
		}
	}
	if !c.DCR.Enabled && c.DCR.Mode != "disabled" {
		c.DCR.Enabled = true
	}
	if c.Invite.TTL == 0 {
		c.Invite.TTL = 24 * time.Hour
	}
	if c.Storage.Driver == "" {
		c.Storage.Driver = "postgres"
	}
	if c.Storage.SQLitePath == "" {
		c.Storage.SQLitePath = "./data/oauth.db"
	}
	if c.Storage.PostgresURL == "" {
		c.Storage.PostgresURL = "postgres://lumen_oauth:lumen_oauth@127.0.0.1:5432/lumen_oauth?sslmode=disable"
	}
	if len(c.DCR.InitialAccessTokens) == 0 {
		c.DCR.InitialAccessTokens = []string{"local-dev-iat"}
	}
	if c.DCR.DefaultTrustLevel == "" {
		c.DCR.DefaultTrustLevel = "unknown_dcr"
	}
	if len(c.DCR.UnknownClientAllowedScopes) == 0 {
		c.DCR.UnknownClientAllowedScopes = []string{"mcp:tools", "offline_access"}
	}
	if len(c.DCR.AllowedRedirects.LoopbackPaths) == 0 {
		c.DCR.AllowedRedirects.LoopbackPaths = []string{"/callback"}
	}
}

func (c Config) Validate() error {
	if c.OAuth.Issuer == "" {
		return errors.New("oauth.issuer cannot be empty")
	}
	if c.OAuth.SigningKey == "" {
		return errors.New("oauth.signing_key cannot be empty")
	}
	if c.OAuth.AccessTokenTTL <= 0 {
		return fmt.Errorf("oauth.access_token_ttl must be > 0, got %s", c.OAuth.AccessTokenTTL)
	}
	if c.Auth.PasswordHash.Algorithm != "pbkdf2-sha256" {
		return fmt.Errorf("unsupported auth.password_hash.algorithm: %q", c.Auth.PasswordHash.Algorithm)
	}
	if c.BootstrapAdmin.Enabled {
		if c.BootstrapAdmin.Email == "" {
			return errors.New("bootstrap_admin.email cannot be empty when enabled")
		}
		if c.BootstrapAdmin.Password == "" {
			return errors.New("bootstrap_admin.password cannot be empty when enabled")
		}
	}
	if c.DCR.IATRequired && c.OAuth.SigningKey == "" {
		return errors.New("dcr.iat_required=true requires oauth.signing_key")
	}
	if c.DCR.IATRequired && len(c.DCR.InitialAccessTokens) == 0 {
		return errors.New("dcr.iat_required=true requires at least one dcr.initial_access_tokens entry")
	}
	switch c.DCR.Mode {
	case "open", "guarded", "iat_required", "disabled":
	default:
		return fmt.Errorf("unsupported dcr.mode: %q", c.DCR.Mode)
	}
	switch c.Storage.Driver {
	case "postgres":
		if c.Storage.PostgresURL == "" {
			return errors.New("storage.postgres_url cannot be empty when storage.driver=postgres")
		}
	case "sqlite":
		if c.Storage.SQLitePath == "" {
			return errors.New("storage.sqlite_path cannot be empty when storage.driver=sqlite")
		}
	default:
		return fmt.Errorf("unsupported storage.driver: %q", c.Storage.Driver)
	}
	return nil
}
