package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/joey/lumen-oauth/internal/application/ports"
	"github.com/joey/lumen-oauth/internal/domain/client"
	"github.com/joey/lumen-oauth/internal/domain/role"
	"github.com/joey/lumen-oauth/internal/domain/token"
)

type fakeSigner struct {
	lastClaims ports.AccessTokenClaims
}

func (f *fakeSigner) SignAccessToken(_ context.Context, claims ports.AccessTokenClaims) (token.AccessToken, error) {
	f.lastClaims = claims
	return token.AccessToken{
		Value:     "signed",
		Subject:   claims.Subject,
		ClientID:  claims.ClientID,
		Scopes:    claims.Scopes,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
	}, nil
}

type fakeClock struct {
	now time.Time
}

func (f fakeClock) Now() time.Time { return f.now }

type fakeID struct {
	value string
}

func (f fakeID) New() string { return f.value }

type fakeRoleRepo struct {
	roles []role.Role
}

func (f fakeRoleRepo) ListForSubject(context.Context, string) ([]role.Role, error) {
	return f.roles, nil
}

func (f fakeRoleRepo) ListRoles(context.Context) ([]role.Role, error) {
	return f.roles, nil
}

func (f fakeRoleRepo) UpsertRoleScopes(context.Context, string, []string) error {
	return nil
}

func (f fakeRoleRepo) BindRoleToSubject(context.Context, string, string) error {
	return nil
}

type fakeClientRepo struct {
	clients map[string]client.OAuthClient
}

func (f fakeClientRepo) GetByID(_ context.Context, clientID string) (client.OAuthClient, error) {
	v, ok := f.clients[clientID]
	if !ok {
		return client.OAuthClient{}, errors.New("not found")
	}
	return v, nil
}

func (f fakeClientRepo) Save(context.Context, client.OAuthClient) error {
	return nil
}

func TestIssueClientCredentials_UsesRequestedScopesWhenRBACMissing(t *testing.T) {
	signer := &fakeSigner{}
	now := time.Unix(1710000000, 0).UTC()
	svc := Service{
		Clients:  newClientRepo("client-a", "secret-a"),
		Signer:   signer,
		Clock:    fakeClock{now: now},
		IDGen:    fakeID{value: "jti-1"},
		Issuer:   "issuer",
		Audience: []string{"aud"},
		TTL:      15 * time.Minute,
	}

	got, err := svc.IssueClientCredentials(context.Background(), "client-a", "secret-a", []string{"routes:write", "routes:read", "routes:read"})
	if err != nil {
		t.Fatalf("IssueClientCredentials() error = %v", err)
	}
	if got.Value == "" {
		t.Fatal("token value should not be empty")
	}
	wantScopes := []string{"routes:read", "routes:write"}
	if len(got.Scopes) != len(wantScopes) || got.Scopes[0] != wantScopes[0] || got.Scopes[1] != wantScopes[1] {
		t.Fatalf("scopes = %#v, want %#v", got.Scopes, wantScopes)
	}
	if signer.lastClaims.JTI != "jti-1" {
		t.Fatalf("jti = %q, want jti-1", signer.lastClaims.JTI)
	}
}

func TestIssueClientCredentials_IntersectScopesWithRBAC(t *testing.T) {
	signer := &fakeSigner{}
	svc := Service{
		Clients: newClientRepo("client-b", "secret-b"),
		Signer:  signer,
		Roles: fakeRoleRepo{roles: []role.Role{
			{Name: "operator", Scopes: []string{"routes:read", "services:read"}},
		}},
		Clock:    fakeClock{now: time.Unix(1710000000, 0).UTC()},
		IDGen:    fakeID{value: "jti-2"},
		Issuer:   "issuer",
		Audience: []string{"aud"},
		TTL:      15 * time.Minute,
	}

	got, err := svc.IssueClientCredentials(context.Background(), "client-b", "secret-b", []string{"routes:write", "routes:read"})
	if err != nil {
		t.Fatalf("IssueClientCredentials() error = %v", err)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "routes:read" {
		t.Fatalf("scopes = %#v, want [routes:read]", got.Scopes)
	}
}

func TestIssueClientCredentials_ReturnsErrNoScopeGranted(t *testing.T) {
	signer := &fakeSigner{}
	svc := Service{
		Clients: newClientRepo("client-c", "secret-c"),
		Signer:  signer,
		Clock:   fakeClock{now: time.Unix(1710000000, 0).UTC()},
		IDGen:   fakeID{value: "jti-3"},
		Issuer:  "issuer",
		TTL:     15 * time.Minute,
	}

	_, err := svc.IssueClientCredentials(context.Background(), "client-c", "secret-c", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err != ErrNoScopeGranted {
		t.Fatalf("err = %v, want ErrNoScopeGranted", err)
	}
}

func TestIssueClientCredentials_InvalidSecret(t *testing.T) {
	signer := &fakeSigner{}
	svc := Service{
		Clients: newClientRepo("client-d", "secret-d"),
		Signer:  signer,
		Clock:   fakeClock{now: time.Unix(1710000000, 0).UTC()},
		IDGen:   fakeID{value: "jti-4"},
		Issuer:  "issuer",
		TTL:     15 * time.Minute,
	}
	_, err := svc.IssueClientCredentials(context.Background(), "client-d", "wrong-secret", []string{"routes:read"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err != ErrInvalidClientCredentials {
		t.Fatalf("err = %v, want ErrInvalidClientCredentials", err)
	}
}

func newClientRepo(clientID, secret string) fakeClientRepo {
	sum := sha256.Sum256([]byte(secret))
	return fakeClientRepo{
		clients: map[string]client.OAuthClient{
			clientID: {
				ID:                 clientID,
				ClientSecretSHA256: hex.EncodeToString(sum[:]),
				Disabled:           false,
			},
		},
	}
}
