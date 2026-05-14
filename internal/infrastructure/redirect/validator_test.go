package redirect

import (
	"context"
	"testing"
)

func TestValidatorTightRedirectMatrix(t *testing.T) {
	validator := Validator{Config: Config{
		LoopbackEnabled: true,
		LoopbackPaths:   []string{"/callback"},
		CustomSchemes:   []string{"cursor://anysphere.cursor-mcp/oauth/callback"},
		HostedHTTPS:     []string{"https://claude.ai/api/mcp/auth_callback"},
	}}

	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "localhost loopback callback", raw: "http://localhost:3118/callback"},
		{name: "127 loopback callback", raw: "http://127.0.0.1:3118/callback"},
		{name: "cursor custom scheme", raw: "cursor://anysphere.cursor-mcp/oauth/callback"},
		{name: "hosted allowlist", raw: "https://claude.ai/api/mcp/auth_callback"},
		{name: "fragment rejected", raw: "http://localhost:3118/callback#code", wantErr: true},
		{name: "wildcard rejected", raw: "https://*.example.com/callback", wantErr: true},
		{name: "public http rejected", raw: "http://example.com/callback", wantErr: true},
		{name: "suffix phishing host rejected", raw: "https://claude.ai.evil.example/api/mcp/auth_callback", wantErr: true},
		{name: "wrong loopback path rejected", raw: "http://localhost:3118/other", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validator.Validate(context.Background(), tt.raw)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
