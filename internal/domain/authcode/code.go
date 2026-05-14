package authcode

import "time"

type AuthorizationCode struct {
	ID                  string
	CodeHash            string
	ClientID            string
	UserID              string
	RedirectURI         string
	Resource            string
	Scopes              []string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
	UsedAt              *time.Time
	CreatedAt           time.Time
}
