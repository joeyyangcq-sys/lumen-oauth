package refreshtoken

import "time"

type RefreshToken struct {
	ID           string
	TokenHash    string
	GrantID      string
	ClientID     string
	UserID       string
	Resource     string
	Scopes       []string
	ExpiresAt    time.Time
	UsedAt       *time.Time
	RevokedAt    *time.Time
	ReplacedByID string
	CreatedAt    time.Time
}
