package invite

import "time"

type Invitation struct {
	Code      string
	Email     string
	Role      string
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}
