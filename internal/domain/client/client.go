package client

type OAuthClient struct {
	ID                 string
	Name               string
	ClientSecretSHA256 string
	GrantTypes         []string
	RedirectURI        []string
	Scopes             []string
	Disabled           bool
}
