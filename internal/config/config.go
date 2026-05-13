package config

import (
	"errors"
	"fmt"
	"time"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Logging       LoggingConfig       `yaml:"logging"`
	Observability ObservabilityConfig `yaml:"observability"`
	OAuth         OAuthConfig         `yaml:"oauth"`
	DCR           DCRConfig           `yaml:"dcr"`
	Invite        InviteConfig        `yaml:"invite"`
	Storage       StorageConfig       `yaml:"storage"`
}

type ServerConfig struct {
	HTTPListen   string        `yaml:"http_listen"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
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
	Issuer         string        `yaml:"issuer"`
	Audience       []string      `yaml:"audience"`
	SigningKey     string        `yaml:"signing_key"`
	AccessTokenTTL time.Duration `yaml:"access_token_ttl"`
}

type DCRConfig struct {
	IATRequired         bool     `yaml:"iat_required"`
	InitialAccessTokens []string `yaml:"initial_access_tokens"`
}

type InviteConfig struct {
	TTL time.Duration `yaml:"ttl"`
}

type StorageConfig struct {
	Driver     string `yaml:"driver"`
	SQLitePath string `yaml:"sqlite_path"`
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
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Logging.Format == "" {
		c.Logging.Format = "json"
	}
	if c.Observability.MetricsPath == "" {
		c.Observability.MetricsPath = "/metrics"
	}
	if c.OAuth.AccessTokenTTL == 0 {
		c.OAuth.AccessTokenTTL = 15 * time.Minute
	}
	if c.Invite.TTL == 0 {
		c.Invite.TTL = 24 * time.Hour
	}
	if c.Storage.Driver == "" {
		c.Storage.Driver = "sqlite"
	}
	if c.Storage.SQLitePath == "" {
		c.Storage.SQLitePath = "./data/oauth.db"
	}
	if len(c.DCR.InitialAccessTokens) == 0 {
		c.DCR.InitialAccessTokens = []string{"local-dev-iat"}
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
	if c.DCR.IATRequired && c.OAuth.SigningKey == "" {
		return errors.New("dcr.iat_required=true requires oauth.signing_key")
	}
	if c.DCR.IATRequired && len(c.DCR.InitialAccessTokens) == 0 {
		return errors.New("dcr.iat_required=true requires at least one dcr.initial_access_tokens entry")
	}
	if c.Storage.Driver != "sqlite" {
		return fmt.Errorf("unsupported storage.driver: %q", c.Storage.Driver)
	}
	if c.Storage.SQLitePath == "" {
		return errors.New("storage.sqlite_path cannot be empty")
	}
	return nil
}
