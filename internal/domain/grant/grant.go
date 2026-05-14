package grant

import "time"

type Grant struct {
	ID        string
	UserID    string
	ClientID  string
	Resource  string
	Scopes    []string
	CreatedAt time.Time
	RevokedAt *time.Time
}
