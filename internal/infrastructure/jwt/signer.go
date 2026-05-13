package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/ports"
	"github.com/joey/lumen-oauth/internal/domain/token"
)

type Signer struct {
	SigningKey string
}

func (s Signer) SignAccessToken(_ context.Context, claims ports.AccessTokenClaims) (token.AccessToken, error) {
	if strings.TrimSpace(s.SigningKey) == "" {
		return token.AccessToken{}, errors.New("signing key is empty")
	}
	header, err := json.Marshal(map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return token.AccessToken{}, err
	}
	payload, err := json.Marshal(map[string]any{
		"iss":       claims.Issuer,
		"sub":       claims.Subject,
		"aud":       claims.Audience,
		"client_id": claims.ClientID,
		"scope":     strings.Join(claims.Scopes, " "),
		"jti":       claims.JTI,
		"iat":       claims.IssuedAt.Unix(),
		"exp":       claims.ExpiresAt.Unix(),
	})
	if err != nil {
		return token.AccessToken{}, err
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	mac := hmac.New(sha256.New, []byte(s.SigningKey))
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return token.AccessToken{
		Value:     signingInput + "." + signature,
		Subject:   claims.Subject,
		ClientID:  claims.ClientID,
		Scopes:    claims.Scopes,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
	}, nil
}
