package config

import "testing"

func TestStorageDefaultsToPostgres(t *testing.T) {
	cfg := Config{
		OAuth: OAuthConfig{
			Issuer:     "http://127.0.0.1:9080",
			SigningKey: "test-signing-key",
		},
	}
	cfg.ApplyDefaults()

	if cfg.Storage.Driver != "postgres" {
		t.Fatalf("storage driver=%q, want postgres", cfg.Storage.Driver)
	}
	if cfg.Storage.PostgresURL == "" {
		t.Fatalf("postgres url should default for local development")
	}
	if cfg.Observability.MetricsPath != "/metrics" {
		t.Fatalf("metrics path=%q, want /metrics", cfg.Observability.MetricsPath)
	}
	if cfg.Observability.PProfPath != "/debug/pprof" {
		t.Fatalf("pprof path=%q, want /debug/pprof", cfg.Observability.PProfPath)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate defaults: %v", err)
	}
}

func TestStorageAllowsSQLiteForTests(t *testing.T) {
	cfg := Config{
		OAuth: OAuthConfig{
			Issuer:     "http://127.0.0.1:9080",
			SigningKey: "test-signing-key",
		},
		Storage: StorageConfig{
			Driver:     "sqlite",
			SQLitePath: ":memory:",
		},
	}
	cfg.ApplyDefaults()

	if cfg.Storage.Driver != "sqlite" {
		t.Fatalf("storage driver=%q, want sqlite", cfg.Storage.Driver)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate sqlite config: %v", err)
	}
}

func TestObservabilityPathValidationRejectsRouteCollisions(t *testing.T) {
	cfg := Config{
		OAuth: OAuthConfig{
			Issuer:     "http://127.0.0.1:9080",
			SigningKey: "test-signing-key",
		},
		Observability: ObservabilityConfig{
			MetricsEnabled: true,
			MetricsPath:    "/healthz",
			PProfPath:      "/debug/pprof",
		},
	}
	cfg.ApplyDefaults()

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected metrics path collision error, got nil")
	}
}

func TestObservabilityPathValidationRequiresAbsolutePath(t *testing.T) {
	cfg := Config{
		OAuth: OAuthConfig{
			Issuer:     "http://127.0.0.1:9080",
			SigningKey: "test-signing-key",
		},
		Observability: ObservabilityConfig{
			MetricsPath: "metrics",
			PProfPath:   "/debug/pprof",
		},
	}
	cfg.ApplyDefaults()
	cfg.Observability.MetricsPath = "metrics"

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected relative metrics path error, got nil")
	}
}
