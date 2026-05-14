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
