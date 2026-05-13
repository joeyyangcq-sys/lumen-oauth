package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/joey/lumen-oauth/internal/application/ports"
)

func TestSignAccessToken_ProducesValidHS256JWT(t *testing.T) {
	claims := ports.AccessTokenClaims{
		Issuer:    "issuer",
		Subject:   "client-a",
		Audience:  []string{"lumen-mcp"},
		ClientID:  "client-a",
		Scopes:    []string{"routes:read", "routes:write"},
		JTI:       "jti-1",
		IssuedAt:  time.Unix(1710000000, 0).UTC(),
		ExpiresAt: time.Unix(1710000900, 0).UTC(),
	}
	s := Signer{SigningKey: "secret-key"}

	tok, err := s.SignAccessToken(context.Background(), claims)
	if err != nil {
		t.Fatalf("SignAccessToken() error = %v", err)
	}

	parts := strings.Split(tok.Value, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt parts = %d, want 3", len(parts))
	}

	mac := hmac.New(sha256.New, []byte("secret-key"))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	wantSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if parts[2] != wantSig {
		t.Fatalf("signature mismatch")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got := payload["scope"]; got != "routes:read routes:write" {
		t.Fatalf("scope = %#v, want %q", got, "routes:read routes:write")
	}
}
