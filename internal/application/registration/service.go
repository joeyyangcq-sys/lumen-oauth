package registration

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/joey/lumen-oauth/internal/application/ports"
	"github.com/joey/lumen-oauth/internal/domain/user"
	"github.com/joey/lumen-oauth/internal/domain/verification"
)

var (
	ErrInvalidEmail       = errors.New("invalid email address")
	ErrInvalidPassword    = errors.New("password must be at least 8 characters")
	ErrEmailAlreadyExists = errors.New("email already registered")
	ErrInvalidCode        = errors.New("invalid or expired verification code")
	ErrAlreadyVerified    = errors.New("email already verified")
	ErrTooManyAttempts    = errors.New("too many verification attempts, please request a new code")
)

const (
	codeTTL         = 10 * time.Minute
	minPasswordLen  = 8
	maxPendingCodes = 5
)

type Service struct {
	Users         ports.UserRepository
	Verifications ports.EmailVerificationRepository
	Passwords     ports.PasswordHasher
	Email         ports.EmailSender
	IDGen         ports.IDGenerator
	Clock         ports.Clock
	DevMode       bool
}

type RegisterCommand struct {
	Email    string
	Password string
	Name     string
}

func (s Service) Register(ctx context.Context, cmd RegisterCommand) error {
	email := strings.TrimSpace(strings.ToLower(cmd.Email))
	if email == "" || !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return ErrInvalidEmail
	}
	if len(strings.TrimSpace(cmd.Password)) < minPasswordLen {
		return ErrInvalidPassword
	}

	if _, err := s.Users.GetUserByEmail(ctx, email); err == nil {
		return ErrEmailAlreadyExists
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	pending, err := s.Verifications.CountPending(ctx, email)
	if err != nil {
		return err
	}
	if pending >= maxPendingCodes {
		return ErrTooManyAttempts
	}

	passwordHash, err := s.Passwords.Hash(cmd.Password)
	if err != nil {
		return err
	}

	code := s.generateCode()
	now := s.Clock.Now().UTC()
	v := verification.EmailVerification{
		ID:        "ev-" + s.IDGen.New(),
		Email:     email,
		Code:      code,
		ExpiresAt: now.Add(codeTTL),
		CreatedAt: now,
	}
	if err := s.Verifications.Save(ctx, v, passwordHash, strings.TrimSpace(cmd.Name)); err != nil {
		return err
	}

	return s.Email.SendVerificationCode(ctx, email, code)
}

func (s Service) VerifyEmail(ctx context.Context, email, code string) error {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || strings.TrimSpace(code) == "" {
		return ErrInvalidCode
	}

	v, passwordHash, name, err := s.Verifications.GetPendingByEmailAndCode(ctx, email, code)
	if err != nil {
		return ErrInvalidCode
	}

	now := s.Clock.Now().UTC()
	if now.After(v.ExpiresAt) {
		return ErrInvalidCode
	}
	if v.VerifiedAt != nil {
		return ErrAlreadyVerified
	}

	if _, err := s.Users.GetUserByEmail(ctx, email); err == nil {
		return ErrEmailAlreadyExists
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	return s.Verifications.MarkVerifiedAndSaveUser(ctx, v.ID, now, user.User{
		ID:           "usr-" + s.IDGen.New(),
		Email:        email,
		Name:         name,
		PasswordHash: passwordHash,
	})
}

const devCode = "111111"

func (s Service) generateCode() string {
	if s.DevMode {
		return devCode
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	n := (int(b[0])<<16 | int(b[1])<<8 | int(b[2])) % 1000000
	return fmt.Sprintf("%06d", n)
}
