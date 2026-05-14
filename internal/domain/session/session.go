package session

import "time"

type Session struct {
	ID            string
	UserID        string
	CSRFTokenHash string
	ExpiresAt     time.Time
	RevokedAt     *time.Time
	CreatedAt     time.Time
}
