package client

type OAuthClient struct {
	ID                      string
	Name                    string
	ClientSecretSHA256      string
	GrantTypes              []string
	ResponseTypes           []string
	RedirectURIs            []string
	Scopes                  []string
	TokenEndpointAuthMethod string
	TrustLevel              string
	ClientIDIssuedAt        int64
	ClientSecretExpiresAt   int64
	Disabled                bool
}
