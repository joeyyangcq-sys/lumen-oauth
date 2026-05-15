package rbac

import (
	"context"
	"errors"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/ports"
	"github.com/joey/lumen-oauth/internal/domain/role"
)

var (
	ErrInvalidRoleName = errors.New("invalid role name")
	ErrInvalidSubject  = errors.New("invalid subject")
)

type Service struct {
	Roles ports.RoleRepository
}

func (s Service) UpsertRoleScopes(ctx context.Context, roleName string, scopes []string) error {
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return ErrInvalidRoleName
	}
	return s.Roles.UpsertRoleScopes(ctx, roleName, scopes)
}

func (s Service) BindRoleToSubject(ctx context.Context, subject, roleName string) error {
	subject = strings.TrimSpace(subject)
	roleName = strings.TrimSpace(roleName)
	if subject == "" {
		return ErrInvalidSubject
	}
	if roleName == "" {
		return ErrInvalidRoleName
	}
	return s.Roles.BindRoleToSubject(ctx, subject, roleName)
}

func (s Service) UnbindRoleFromSubject(ctx context.Context, subject, roleName string) error {
	subject = strings.TrimSpace(subject)
	roleName = strings.TrimSpace(roleName)
	if subject == "" {
		return ErrInvalidSubject
	}
	if roleName == "" {
		return ErrInvalidRoleName
	}
	return s.Roles.UnbindRoleFromSubject(ctx, subject, roleName)
}

func (s Service) DeleteRole(ctx context.Context, roleName string) error {
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return ErrInvalidRoleName
	}
	return s.Roles.DeleteRole(ctx, roleName)
}

func (s Service) ListRoles(ctx context.Context) ([]role.Role, error) {
	return s.Roles.ListRoles(ctx)
}
