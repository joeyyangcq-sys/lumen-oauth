package jwks

import (
	"context"
	"encoding/base64"
)

type Provider struct {
	Issuer     string
	SigningKey string
}

func (p Provider) PublicJWKS(_ context.Context) (map[string]any, error) {
	keys := []any{}
	if p.SigningKey != "" {
		keys = append(keys, map[string]any{
			"kty": "oct",
			"kid": "default",
			"alg": "HS256",
			"use": "sig",
			"k":   base64.RawURLEncoding.EncodeToString([]byte(p.SigningKey)),
		})
	}
	return map[string]any{
		"issuer": p.Issuer,
		"keys":   keys,
	}, nil
}
