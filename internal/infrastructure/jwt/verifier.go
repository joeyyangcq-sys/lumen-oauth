package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/joey/lumen-oauth/internal/application/ports"
)

var (
	ErrMissingBearer  = errors.New("missing bearer token")
	ErrMalformedToken = errors.New("malformed access token")
	ErrInvalidAlg     = errors.New("invalid access token alg")
	ErrInvalidSig     = errors.New("invalid access token signature")
	ErrTokenExpired   = errors.New("access token expired")
)

type Verifier struct {
	SigningKey string
	Now        func() time.Time
}

type jwtHeader struct {
	Alg string `json:"alg"`
}

type jwtClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      []string `json:"aud"`
	ClientID string   `json:"client_id"`
	Scope    string   `json:"scope"`
	JTI      string   `json:"jti"`
	Iat      int64    `json:"iat"`
	Exp      int64    `json:"exp"`
}

func (v Verifier) VerifyAccessToken(_ context.Context, bearer string) (ports.AccessTokenClaims, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(bearer), "Bearer "))
	if raw == "" {
		return ports.AccessTokenClaims{}, ErrMissingBearer
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ports.AccessTokenClaims{}, ErrMalformedToken
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ports.AccessTokenClaims{}, ErrMalformedToken
	}
	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ports.AccessTokenClaims{}, ErrMalformedToken
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ports.AccessTokenClaims{}, ErrMalformedToken
	}
	var header jwtHeader
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return ports.AccessTokenClaims{}, ErrMalformedToken
	}
	if !strings.EqualFold(header.Alg, "HS256") {
		return ports.AccessTokenClaims{}, ErrInvalidAlg
	}
	mac := hmac.New(sha256.New, []byte(v.SigningKey))
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	if subtle.ConstantTimeCompare(mac.Sum(nil), signature) != 1 {
		return ports.AccessTokenClaims{}, ErrInvalidSig
	}
	var claims jwtClaims
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return ports.AccessTokenClaims{}, ErrMalformedToken
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	if claims.Exp > 0 && now.Unix() >= claims.Exp {
		return ports.AccessTokenClaims{}, ErrTokenExpired
	}
	return ports.AccessTokenClaims{
		Issuer:    claims.Iss,
		Subject:   claims.Sub,
		Audience:  claims.Aud,
		ClientID:  claims.ClientID,
		Scopes:    strings.Fields(claims.Scope),
		JTI:       claims.JTI,
		IssuedAt:  time.Unix(claims.Iat, 0).UTC(),
		ExpiresAt: time.Unix(claims.Exp, 0).UTC(),
	}, nil
}
