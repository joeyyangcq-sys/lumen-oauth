package user

import "time"

type User struct {
	ID                  string
	Email               string
	Name                string
	PasswordHash        string
	IsAdmin             bool
	Disabled            bool
	ForceChangePassword bool
	LastLoginAt         *time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}
