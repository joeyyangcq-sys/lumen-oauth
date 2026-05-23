package sqlite

import (
	"context"
	"time"

	"github.com/joey/lumen-oauth/internal/domain/user"
	"github.com/joey/lumen-oauth/internal/domain/verification"
)

type VerificationAdapter struct {
	Repos Repositories
}

func (a VerificationAdapter) Save(ctx context.Context, v verification.EmailVerification, passwordHash, name string) error {
	return a.Repos.SaveEmailVerification(ctx, v, passwordHash, name)
}

func (a VerificationAdapter) GetPendingByEmailAndCode(ctx context.Context, email, code string) (verification.EmailVerification, string, string, error) {
	return a.Repos.GetPendingByEmailAndCode(ctx, email, code)
}

func (a VerificationAdapter) MarkVerified(ctx context.Context, id string, at time.Time) error {
	return a.Repos.MarkEmailVerified(ctx, id, at)
}

func (a VerificationAdapter) MarkVerifiedAndSaveUser(ctx context.Context, verificationID string, at time.Time, in user.User) error {
	return a.Repos.MarkEmailVerifiedAndSaveUser(ctx, verificationID, at, in)
}

func (a VerificationAdapter) CountPending(ctx context.Context, email string) (int, error) {
	return a.Repos.CountPendingVerifications(ctx, email)
}
