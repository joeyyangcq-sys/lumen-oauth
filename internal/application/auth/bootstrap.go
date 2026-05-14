package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/joey/lumen-oauth/internal/domain/user"
)

type BootstrapAdminCommand struct {
	Enabled             bool
	Email               string
	Password            string
	Name                string
	ForceChangePassword bool
}

func (s Service) EnsureBootstrapAdmin(ctx context.Context, cmd BootstrapAdminCommand) error {
	if !cmd.Enabled {
		return nil
	}
	if s.Users == nil || s.Passwords == nil {
		return errors.New("bootstrap admin dependencies are missing")
	}
	email := strings.TrimSpace(strings.ToLower(cmd.Email))
	if email == "" || strings.TrimSpace(cmd.Password) == "" {
		return ErrInvalidCredentials
	}
	if _, err := s.Users.GetUserByEmail(ctx, email); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	passwordHash, err := s.Passwords.Hash(cmd.Password)
	if err != nil {
		return err
	}
	id := "usr-bootstrap-admin"
	if s.IDGen != nil {
		id = "usr-" + s.IDGen.New()
	}
	name := strings.TrimSpace(cmd.Name)
	if name == "" {
		name = "Default Admin"
	}
	return s.Users.SaveUser(ctx, user.User{
		ID:                  id,
		Email:               email,
		Name:                name,
		PasswordHash:        passwordHash,
		IsAdmin:             true,
		ForceChangePassword: cmd.ForceChangePassword,
	})
}
