package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/joey/lumen-oauth/internal/application/ports"
	"github.com/joey/lumen-oauth/internal/domain/authcode"
	"github.com/joey/lumen-oauth/internal/domain/grant"
	"github.com/joey/lumen-oauth/internal/domain/refreshtoken"
	"github.com/joey/lumen-oauth/internal/domain/token"
)

var (
	ErrInvalidClientID          = errors.New("invalid client_id")
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
	ErrClientDisabled           = errors.New("client is disabled")
	ErrNoScopeGranted           = errors.New("no scopes granted")
	ErrInvalidCredentials       = errors.New("invalid email or password")
	ErrUserDisabled             = errors.New("user is disabled")
	ErrUnauthorized             = errors.New("unauthorized")
	ErrInvalidAuthorizeRequest  = errors.New("invalid authorization request")
	ErrInvalidAuthorizationCode = errors.New("invalid authorization code")
	ErrPKCEVerificationFailed   = errors.New("pkce verification failed")
	ErrInvalidRefreshToken      = errors.New("invalid refresh token")
	ErrRefreshTokenReuse        = errors.New("refresh token reuse detected")
)

type Service struct {
	Clients    ports.ClientRepository
	Users      ports.UserRepository
	AuthCodes  ports.AuthorizationCodeRepository
	Grants     ports.GrantRepository
	Refreshes  ports.RefreshTokenRepository
	Signer     ports.TokenSigner
	Verifier   ports.TokenVerifier
	Passwords  ports.PasswordHasher
	Roles      ports.RoleRepository
	IDGen      ports.IDGenerator
	AuditSink  ports.AuditSink
	Clock      ports.Clock
	Issuer     string
	Audience   []string
	TTL        time.Duration
	CodeTTL    time.Duration
	RefreshTTL time.Duration
}

type LoginResult struct {
	AccessToken token.AccessToken
	User        UserSession
}

type UserSession struct {
	ID                  string   `json:"id"`
	Email               string   `json:"email"`
	Name                string   `json:"name"`
	IsAdmin             bool     `json:"is_admin"`
	ForceChangePassword bool     `json:"force_change_password"`
	Scopes              []string `json:"scopes"`
}

type AuthorizeCommand struct {
	Bearer              string
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

type AuthorizeResult struct {
	Code        string
	State       string
	RedirectURI string
}

type AuthorizationCodeTokenCommand struct {
	Code         string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	CodeVerifier string
	Resource     string
}

type RefreshTokenCommand struct {
	RefreshToken string
	ClientID     string
	Resource     string
}

type OAuthTokenResult struct {
	AccessToken  token.AccessToken
	RefreshToken string
}

func (s Service) Login(ctx context.Context, email, password string) (LoginResult, error) {
	if s.Users == nil || s.Passwords == nil || s.Signer == nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || strings.TrimSpace(password) == "" {
		return LoginResult{}, ErrInvalidCredentials
	}
	u, err := s.Users.GetUserByEmail(ctx, email)
	if err != nil {
		return LoginResult{}, ErrInvalidCredentials
	}
	if u.Disabled {
		return LoginResult{}, ErrUserDisabled
	}
	ok, err := s.Passwords.Verify(password, u.PasswordHash)
	if err != nil || !ok {
		return LoginResult{}, ErrInvalidCredentials
	}
	now := s.now()
	_ = s.Users.UpdateUserLastLogin(ctx, u.ID, now)
	scopes := userLoginScopes(u.IsAdmin)
	jti := ""
	if s.IDGen != nil {
		jti = s.IDGen.New()
	}
	issued, err := s.Signer.SignAccessToken(ctx, ports.AccessTokenClaims{
		Issuer:    s.Issuer,
		Subject:   u.ID,
		Audience:  s.Audience,
		Scopes:    scopes,
		JTI:       jti,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.TTL),
	})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{
		AccessToken: issued,
		User:        userSession(u.ID, u.Email, u.Name, u.IsAdmin, u.ForceChangePassword, scopes),
	}, nil
}

func (s Service) Me(ctx context.Context, bearer string) (UserSession, error) {
	if s.Users == nil || s.Verifier == nil {
		return UserSession{}, ErrUnauthorized
	}
	claims, err := s.Verifier.VerifyAccessToken(ctx, bearer)
	if err != nil {
		return UserSession{}, ErrUnauthorized
	}
	u, err := s.Users.GetUserByID(ctx, claims.Subject)
	if err != nil || u.Disabled {
		return UserSession{}, ErrUnauthorized
	}
	return userSession(u.ID, u.Email, u.Name, u.IsAdmin, u.ForceChangePassword, claims.Scopes), nil
}

func (s Service) Authorize(ctx context.Context, cmd AuthorizeCommand) (AuthorizeResult, error) {
	if s.Clients == nil || s.Users == nil || s.Verifier == nil || s.AuthCodes == nil || s.Grants == nil {
		return AuthorizeResult{}, ErrInvalidAuthorizeRequest
	}
	if cmd.ResponseType != "code" || cmd.CodeChallengeMethod != "S256" || strings.TrimSpace(cmd.CodeChallenge) == "" {
		return AuthorizeResult{}, ErrInvalidAuthorizeRequest
	}
	claims, err := s.Verifier.VerifyAccessToken(ctx, cmd.Bearer)
	if err != nil {
		return AuthorizeResult{}, ErrUnauthorized
	}
	u, err := s.Users.GetUserByID(ctx, claims.Subject)
	if err != nil || u.Disabled {
		return AuthorizeResult{}, ErrUnauthorized
	}
	c, err := s.Clients.GetByID(ctx, cmd.ClientID)
	if err != nil || c.Disabled || c.TrustLevel == "blocked" {
		return AuthorizeResult{}, ErrInvalidAuthorizeRequest
	}
	if !contains(c.GrantTypes, "authorization_code") || !contains(c.ResponseTypes, "code") {
		return AuthorizeResult{}, ErrInvalidAuthorizeRequest
	}
	if !contains(c.RedirectURIs, cmd.RedirectURI) {
		return AuthorizeResult{}, ErrInvalidAuthorizeRequest
	}
	resource := strings.TrimSpace(cmd.Resource)
	if resource == "" && len(s.Audience) > 0 {
		resource = s.Audience[0]
	}
	if resource == "" || !contains(s.Audience, resource) {
		return AuthorizeResult{}, ErrInvalidAuthorizeRequest
	}
	scopes := grantScopes(cmd.Scope, c.Scopes)
	if len(scopes) == 0 {
		return AuthorizeResult{}, ErrNoScopeGranted
	}
	now := s.now()
	rawCode := "code-local-dev"
	codeID := "ac-local-dev"
	grantID := "grant-local-dev"
	if s.IDGen != nil {
		rawCode = "code-" + s.IDGen.New()
		codeID = "ac-" + s.IDGen.New()
		grantID = "grant-" + s.IDGen.New()
	}
	if err := s.Grants.UpsertGrant(ctx, grant.Grant{
		ID:       grantID,
		UserID:   u.ID,
		ClientID: c.ID,
		Resource: resource,
		Scopes:   scopes,
	}); err != nil {
		return AuthorizeResult{}, err
	}
	codeTTL := s.CodeTTL
	if codeTTL <= 0 {
		codeTTL = 5 * time.Minute
	}
	if err := s.AuthCodes.SaveAuthorizationCode(ctx, authcode.AuthorizationCode{
		ID:                  codeID,
		CodeHash:            hashOpaque(rawCode),
		ClientID:            c.ID,
		UserID:              u.ID,
		RedirectURI:         cmd.RedirectURI,
		Resource:            resource,
		Scopes:              scopes,
		CodeChallenge:       cmd.CodeChallenge,
		CodeChallengeMethod: cmd.CodeChallengeMethod,
		ExpiresAt:           now.Add(codeTTL),
	}); err != nil {
		return AuthorizeResult{}, err
	}
	return AuthorizeResult{Code: rawCode, State: cmd.State, RedirectURI: cmd.RedirectURI}, nil
}

func (s Service) ExchangeAuthorizationCode(ctx context.Context, cmd AuthorizationCodeTokenCommand) (OAuthTokenResult, error) {
	if s.AuthCodes == nil || s.Clients == nil || s.Signer == nil {
		return OAuthTokenResult{}, ErrInvalidAuthorizationCode
	}
	c, err := s.Clients.GetByID(ctx, cmd.ClientID)
	if err != nil || c.Disabled || c.TrustLevel == "blocked" {
		return OAuthTokenResult{}, ErrInvalidAuthorizationCode
	}
	if c.TokenEndpointAuthMethod != "none" {
		if err := s.validateClientCredentials(ctx, cmd.ClientID, cmd.ClientSecret); err != nil {
			return OAuthTokenResult{}, err
		}
	}
	codeHash := hashOpaque(cmd.Code)
	stored, err := s.AuthCodes.GetAuthorizationCodeByHash(ctx, codeHash)
	if err != nil || stored.UsedAt != nil {
		return OAuthTokenResult{}, ErrInvalidAuthorizationCode
	}
	now := s.now()
	if now.After(stored.ExpiresAt) {
		return OAuthTokenResult{}, ErrInvalidAuthorizationCode
	}
	if stored.ClientID != cmd.ClientID || stored.RedirectURI != cmd.RedirectURI {
		return OAuthTokenResult{}, ErrInvalidAuthorizationCode
	}
	if strings.TrimSpace(cmd.Resource) != "" && stored.Resource != strings.TrimSpace(cmd.Resource) {
		return OAuthTokenResult{}, ErrInvalidAuthorizationCode
	}
	if !verifyPKCES256(cmd.CodeVerifier, stored.CodeChallenge) {
		return OAuthTokenResult{}, ErrPKCEVerificationFailed
	}
	if err := s.AuthCodes.MarkAuthorizationCodeUsed(ctx, codeHash, now); err != nil {
		return OAuthTokenResult{}, ErrInvalidAuthorizationCode
	}
	grant, err := s.Grants.GetActiveGrant(ctx, stored.UserID, stored.ClientID, stored.Resource)
	if err != nil {
		return OAuthTokenResult{}, ErrInvalidAuthorizationCode
	}
	return s.issueForGrant(ctx, grant, now)
}

func (s Service) Refresh(ctx context.Context, cmd RefreshTokenCommand) (OAuthTokenResult, error) {
	if s.Refreshes == nil || s.Grants == nil || s.Clients == nil {
		return OAuthTokenResult{}, ErrInvalidRefreshToken
	}
	stored, err := s.Refreshes.GetRefreshTokenByHash(ctx, hashOpaque(cmd.RefreshToken))
	if err != nil {
		return OAuthTokenResult{}, ErrInvalidRefreshToken
	}
	now := s.now()
	if stored.UsedAt != nil || stored.RevokedAt != nil {
		_ = s.Refreshes.RevokeRefreshTokensByGrant(ctx, stored.GrantID, now)
		return OAuthTokenResult{}, ErrRefreshTokenReuse
	}
	if now.After(stored.ExpiresAt) || stored.ClientID != cmd.ClientID {
		return OAuthTokenResult{}, ErrInvalidRefreshToken
	}
	if strings.TrimSpace(cmd.Resource) != "" && stored.Resource != strings.TrimSpace(cmd.Resource) {
		return OAuthTokenResult{}, ErrInvalidRefreshToken
	}
	c, err := s.Clients.GetByID(ctx, stored.ClientID)
	if err != nil || c.Disabled || c.TrustLevel == "blocked" {
		return OAuthTokenResult{}, ErrInvalidRefreshToken
	}
	grant, err := s.Grants.GetActiveGrant(ctx, stored.UserID, stored.ClientID, stored.Resource)
	if err != nil {
		return OAuthTokenResult{}, ErrInvalidRefreshToken
	}
	result, err := s.issueAccessForGrant(ctx, grant, now)
	if err != nil {
		return OAuthTokenResult{}, err
	}
	nextRaw, next, err := s.newRefreshToken(grant, now)
	if err != nil {
		return OAuthTokenResult{}, err
	}
	if err := s.Refreshes.RotateRefreshToken(ctx, stored.TokenHash, next, now); err != nil {
		return OAuthTokenResult{}, ErrInvalidRefreshToken
	}
	result.RefreshToken = nextRaw
	return result, nil
}

func (s Service) issueForGrant(ctx context.Context, grant grant.Grant, now time.Time) (OAuthTokenResult, error) {
	result, err := s.issueAccessForGrant(ctx, grant, now)
	if err != nil {
		return OAuthTokenResult{}, err
	}
	if contains(grant.Scopes, "offline_access") && s.Refreshes != nil {
		raw, refresh, err := s.newRefreshToken(grant, now)
		if err != nil {
			return OAuthTokenResult{}, err
		}
		if err := s.Refreshes.SaveRefreshToken(ctx, refresh); err != nil {
			return OAuthTokenResult{}, err
		}
		result.RefreshToken = raw
	}
	return result, nil
}

func (s Service) issueAccessForGrant(ctx context.Context, grant grant.Grant, now time.Time) (OAuthTokenResult, error) {
	jti := ""
	if s.IDGen != nil {
		jti = s.IDGen.New()
	}
	access, err := s.Signer.SignAccessToken(ctx, ports.AccessTokenClaims{
		Issuer:    s.Issuer,
		Subject:   grant.UserID,
		Audience:  []string{grant.Resource},
		ClientID:  grant.ClientID,
		Scopes:    grant.Scopes,
		JTI:       jti,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.TTL),
	})
	if err != nil {
		return OAuthTokenResult{}, err
	}
	return OAuthTokenResult{AccessToken: access}, nil
}

func (s Service) newRefreshToken(grant grant.Grant, now time.Time) (string, refreshtoken.RefreshToken, error) {
	raw := "rt-local-dev"
	id := "rt-local-dev"
	if s.IDGen != nil {
		raw = "rt-" + s.IDGen.New()
		id = "rt-" + s.IDGen.New()
	}
	ttl := s.RefreshTTL
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	return raw, refreshtoken.RefreshToken{
		ID:        id,
		TokenHash: hashOpaque(raw),
		GrantID:   grant.ID,
		ClientID:  grant.ClientID,
		UserID:    grant.UserID,
		Resource:  grant.Resource,
		Scopes:    grant.Scopes,
		ExpiresAt: now.Add(ttl),
	}, nil
}

func (s Service) IssueClientCredentials(ctx context.Context, clientID, clientSecret string, requestedScopes []string) (token.AccessToken, error) {
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return token.AccessToken{}, ErrInvalidClientID
	}
	if err := s.validateClientCredentials(ctx, clientID, clientSecret); err != nil {
		return token.AccessToken{}, err
	}

	allowedScopes, err := s.resolveAllowedScopes(ctx, clientID)
	if err != nil {
		return token.AccessToken{}, err
	}
	if s.Roles != nil && len(allowedScopes) == 0 {
		return token.AccessToken{}, ErrNoScopeGranted
	}
	grantedScopes := grantScopes(requestedScopes, allowedScopes)
	if len(grantedScopes) == 0 {
		return token.AccessToken{}, ErrNoScopeGranted
	}

	now := s.now()
	jti := ""
	if s.IDGen != nil {
		jti = s.IDGen.New()
	}
	claims := ports.AccessTokenClaims{
		Issuer:    s.Issuer,
		Subject:   clientID,
		Audience:  s.Audience,
		ClientID:  clientID,
		Scopes:    grantedScopes,
		JTI:       jti,
		IssuedAt:  now,
		ExpiresAt: now.Add(s.TTL),
	}
	signed, err := s.Signer.SignAccessToken(ctx, claims)
	if err != nil {
		return token.AccessToken{}, err
	}
	return signed, nil
}

func (s Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func userLoginScopes(isAdmin bool) []string {
	if isAdmin {
		return []string{"admin", "email", "openid", "profile"}
	}
	return []string{"email", "openid", "profile"}
}

func userSession(id, email, name string, isAdmin, forceChangePassword bool, scopes []string) UserSession {
	return UserSession{
		ID:                  id,
		Email:               email,
		Name:                name,
		IsAdmin:             isAdmin,
		ForceChangePassword: forceChangePassword,
		Scopes:              normalizeScopes(scopes),
	}
}

func (s Service) validateClientCredentials(ctx context.Context, clientID, clientSecret string) error {
	if s.Clients == nil {
		return ErrInvalidClientCredentials
	}
	stored, err := s.Clients.GetByID(ctx, clientID)
	if err != nil {
		return ErrInvalidClientCredentials
	}
	if stored.Disabled {
		return ErrClientDisabled
	}
	providedHash := sha256.Sum256([]byte(clientSecret))
	providedHashHex := hex.EncodeToString(providedHash[:])
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(stored.ClientSecretSHA256)), []byte(strings.ToLower(providedHashHex))) != 1 {
		return ErrInvalidClientCredentials
	}
	return nil
}

func (s Service) resolveAllowedScopes(ctx context.Context, clientID string) ([]string, error) {
	if s.Roles == nil {
		return nil, nil
	}
	roles, err := s.Roles.ListForSubject(ctx, clientID)
	if err != nil {
		return nil, err
	}
	set := make(map[string]struct{}, 8)
	for _, r := range roles {
		for _, scope := range r.Scopes {
			scope = strings.TrimSpace(scope)
			if scope == "" {
				continue
			}
			set[scope] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return out, nil
}

func grantScopes(requested, allowed []string) []string {
	requested = normalizeScopes(requested)
	allowed = normalizeScopes(allowed)

	// No RBAC source configured yet: allow requested scopes.
	if len(allowed) == 0 {
		return requested
	}
	// No explicit request: grant full allowed scope set.
	if len(requested) == 0 {
		return allowed
	}

	allowSet := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		allowSet[s] = struct{}{}
	}
	granted := make([]string, 0, len(requested))
	for _, scope := range requested {
		if _, ok := allowSet[scope]; ok {
			granted = append(granted, scope)
		}
	}
	slices.Sort(granted)
	return granted
}

func normalizeScopes(scopes []string) []string {
	set := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		set[scope] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for scope := range set {
		out = append(out, scope)
	}
	slices.Sort(out)
	return out
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}

func hashOpaque(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func verifyPKCES256(verifier, challenge string) bool {
	if strings.TrimSpace(verifier) == "" || strings.TrimSpace(challenge) == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}
