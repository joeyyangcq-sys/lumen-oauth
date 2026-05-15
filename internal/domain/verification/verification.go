package verification

import "time"

type EmailVerification struct {
	ID         string
	Email      string
	Code       string
	ExpiresAt  time.Time
	VerifiedAt *time.Time
	CreatedAt  time.Time
}
