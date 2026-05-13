package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/joey/lumen-oauth/internal/application/ports"
	"github.com/joey/lumen-oauth/internal/domain/token"
)

var (
	ErrInvalidClientID          = errors.New("invalid client_id")
	ErrInvalidClientCredentials = errors.New("invalid client credentials")
	ErrClientDisabled           = errors.New("client is disabled")
	ErrNoScopeGranted           = errors.New("no scopes granted")
)

type Service struct {
	Clients   ports.ClientRepository
	Signer    ports.TokenSigner
	Roles     ports.RoleRepository
	IDGen     ports.IDGenerator
	AuditSink ports.AuditSink
	Clock     ports.Clock
	Issuer    string
	Audience  []string
	TTL       time.Duration
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

	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock.Now().UTC()
	}
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
