package ports

import (
	"context"
	"time"

	"github.com/joey/lumen-oauth/internal/domain/authcode"
	"github.com/joey/lumen-oauth/internal/domain/client"
	"github.com/joey/lumen-oauth/internal/domain/grant"
	"github.com/joey/lumen-oauth/internal/domain/invite"
	"github.com/joey/lumen-oauth/internal/domain/refreshtoken"
	"github.com/joey/lumen-oauth/internal/domain/role"
	"github.com/joey/lumen-oauth/internal/domain/session"
	"github.com/joey/lumen-oauth/internal/domain/token"
	"github.com/joey/lumen-oauth/internal/domain/user"
	"github.com/joey/lumen-oauth/internal/domain/verification"
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

type TokenVerifier interface {
	VerifyAccessToken(ctx context.Context, bearer string) (AccessTokenClaims, error)
}

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, encodedHash string) (bool, error)
}

type JWKSProvider interface {
	PublicJWKS(ctx context.Context) (map[string]any, error)
}

type UserRepository interface {
	GetUserByID(ctx context.Context, id string) (user.User, error)
	GetUserByEmail(ctx context.Context, email string) (user.User, error)
	SaveUser(ctx context.Context, in user.User) error
	UpdateUserLastLogin(ctx context.Context, id string, at time.Time) error
}

type ClientRepository interface {
	GetByID(ctx context.Context, clientID string) (client.OAuthClient, error)
	Save(ctx context.Context, in client.OAuthClient) error
}

type RedirectURIValidator interface {
	Validate(ctx context.Context, raw string) (string, error)
}

type AuthorizationCodeRepository interface {
	SaveAuthorizationCode(ctx context.Context, code authcode.AuthorizationCode) error
	GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (authcode.AuthorizationCode, error)
	MarkAuthorizationCodeUsed(ctx context.Context, codeHash string, usedAt time.Time) error
	MarkAuthorizationCodeUsedAndSaveRefreshToken(ctx context.Context, codeHash string, usedAt time.Time, refresh *refreshtoken.RefreshToken) error
}

type GrantRepository interface {
	UpsertGrant(ctx context.Context, in grant.Grant) error
	GetActiveGrant(ctx context.Context, userID, clientID, resource string) (grant.Grant, error)
}

type RefreshTokenRepository interface {
	SaveRefreshToken(ctx context.Context, token refreshtoken.RefreshToken) error
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (refreshtoken.RefreshToken, error)
	RotateRefreshToken(ctx context.Context, oldHash string, next refreshtoken.RefreshToken, usedAt time.Time) error
	RevokeRefreshTokensByGrant(ctx context.Context, grantID string, revokedAt time.Time) error
}

type SessionRepository interface {
	SaveSession(ctx context.Context, session session.Session) error
	GetSessionByID(ctx context.Context, id string) (session.Session, error)
	RevokeSession(ctx context.Context, id string, revokedAt time.Time) error
}

type RoleRepository interface {
	ListForSubject(ctx context.Context, subject string) ([]role.Role, error)
	ListRoles(ctx context.Context) ([]role.Role, error)
	UpsertRoleScopes(ctx context.Context, roleName string, scopes []string) error
	BindRoleToSubject(ctx context.Context, subject, roleName string) error
	UnbindRoleFromSubject(ctx context.Context, subject, roleName string) error
	DeleteRole(ctx context.Context, roleName string) error
}

type InvitationRepository interface {
	Create(ctx context.Context, in invite.Invitation) error
	GetByCode(ctx context.Context, code string) (invite.Invitation, error)
	MarkUsed(ctx context.Context, code string, usedAt time.Time) error
}

type EmailVerificationRepository interface {
	Save(ctx context.Context, v verification.EmailVerification, passwordHash, name string) error
	GetPendingByEmailAndCode(ctx context.Context, email, code string) (verification.EmailVerification, string, string, error)
	MarkVerified(ctx context.Context, id string, at time.Time) error
	MarkVerifiedAndSaveUser(ctx context.Context, verificationID string, at time.Time, in user.User) error
	CountPending(ctx context.Context, email string) (int, error)
}

type EmailSender interface {
	SendVerificationCode(ctx context.Context, to, code string) error
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
