package invite

import (
	"context"
	"errors"
	"strings"
	"time"

	appports "github.com/joey/lumen-oauth/internal/application/ports"
	"github.com/joey/lumen-oauth/internal/domain/invite"
)

var (
	ErrInvalidEmail      = errors.New("invalid email")
	ErrInviteExpired     = errors.New("invitation expired")
	ErrInviteUsed        = errors.New("invitation already used")
	ErrInviteRevoked     = errors.New("invitation revoked")
	ErrInviteNotFound    = errors.New("invitation not found")
	ErrInvalidInviteCode = errors.New("invalid invite code")
)

type Service struct {
	Invites   appports.InvitationRepository
	Roles     appports.RoleRepository
	IDGen     appports.IDGenerator
	Clock     appports.Clock
	InviteTTL time.Duration
	AuditSink appports.AuditSink
}

type AcceptResult struct {
	Subject string `json:"subject"`
	Role    string `json:"role"`
}

func (s Service) CreateInvitation(ctx context.Context, email, roleName string) (invite.Invitation, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || !strings.Contains(email, "@") {
		return invite.Invitation{}, ErrInvalidEmail
	}
	if strings.TrimSpace(roleName) == "" {
		roleName = "gateway-operator"
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock.Now().UTC()
	}
	ttl := s.InviteTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	code := "inv-local-dev"
	if s.IDGen != nil {
		code = "inv-" + s.IDGen.New()
	}
	out := invite.Invitation{
		Code:      code,
		Email:     email,
		Role:      roleName,
		ExpiresAt: now.Add(ttl),
	}
	if err := s.Invites.Create(ctx, out); err != nil {
		return invite.Invitation{}, err
	}
	return out, nil
}

func (s Service) AcceptInvitation(ctx context.Context, code, subject string) (AcceptResult, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return AcceptResult{}, ErrInvalidInviteCode
	}
	inv, err := s.Invites.GetByCode(ctx, code)
	if err != nil {
		return AcceptResult{}, ErrInviteNotFound
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock.Now().UTC()
	}
	if inv.RevokedAt != nil {
		return AcceptResult{}, ErrInviteRevoked
	}
	if inv.UsedAt != nil {
		return AcceptResult{}, ErrInviteUsed
	}
	if now.After(inv.ExpiresAt) {
		return AcceptResult{}, ErrInviteExpired
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		subject = inv.Email
	}
	roleName := strings.TrimSpace(inv.Role)
	if roleName != "" {
		if err := s.Roles.BindRoleToSubject(ctx, subject, roleName); err != nil {
			return AcceptResult{}, err
		}
	}
	if err := s.Invites.MarkUsed(ctx, code, now); err != nil {
		return AcceptResult{}, err
	}
	return AcceptResult{Subject: subject, Role: roleName}, nil
}
