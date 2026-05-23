package sqlite

import (
	"os"
	"testing"
)

func TestPostgresOpenAndSeedIntegration(t *testing.T) {
	url := os.Getenv("LUMEN_OAUTH_POSTGRES_URL")
	if url == "" {
		t.Skip("set LUMEN_OAUTH_POSTGRES_URL to run postgres integration test")
	}

	repos, err := OpenPostgresAndInit(url)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer func() { _ = repos.Close() }()

	client, err := repos.GetByID(t.Context(), "local-dev-client")
	if err != nil {
		t.Fatalf("get seeded client: %v", err)
	}
	if client.ID != "local-dev-client" || client.Disabled {
		t.Fatalf("unexpected seeded client: %+v", client)
	}
}
