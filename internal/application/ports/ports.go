package ports

import (
	"context"
	"time"

	"github.com/joey/lumen-oauth/internal/domain/client"
	"github.com/joey/lumen-oauth/internal/domain/invite"
	"github.com/joey/lumen-oauth/internal/domain/role"
	"github.com/joey/lumen-oauth/internal/domain/token"
)

type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	New() string
}

type TokenSigner interface {
	SignAccessToken(ctx context.Context, claims AccessTokenClaims) (token.AccessToken, error)
}

type JWKSProvider interface {
	PublicJWKS(ctx context.Context) (map[string]any, error)
}

type ClientRepository interface {
	GetByID(ctx context.Context, clientID string) (client.OAuthClient, error)
	Save(ctx context.Context, in client.OAuthClient) error
}

type RoleRepository interface {
	ListForSubject(ctx context.Context, subject string) ([]role.Role, error)
	ListRoles(ctx context.Context) ([]role.Role, error)
	UpsertRoleScopes(ctx context.Context, roleName string, scopes []string) error
	BindRoleToSubject(ctx context.Context, subject, roleName string) error
}

type InvitationRepository interface {
	Create(ctx context.Context, in invite.Invitation) error
	GetByCode(ctx context.Context, code string) (invite.Invitation, error)
	MarkUsed(ctx context.Context, code string, usedAt time.Time) error
}

type AuditSink interface {
	Record(ctx context.Context, event AuditEvent) error
}

type AccessTokenClaims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ClientID  string
	Scopes    []string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type AuditEvent struct {
	Action    string
	Actor     string
	ClientID  string
	Result    string
	TraceID   string
	Timestamp time.Time
	Details   map[string]any
}
