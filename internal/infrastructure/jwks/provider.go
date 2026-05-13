package jwks

import "context"

type Provider struct {
	Issuer string
}

func (p Provider) PublicJWKS(_ context.Context) (map[string]any, error) {
	// TODO: expose real signing public keys with kid/alg metadata.
	return map[string]any{
		"issuer": p.Issuer,
		"keys":   []any{},
	}, nil
}
