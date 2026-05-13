package token

import "time"

type AccessToken struct {
	Value     string
	Subject   string
	ClientID  string
	Scopes    []string
	ExpiresAt time.Time
	IssuedAt  time.Time
}
