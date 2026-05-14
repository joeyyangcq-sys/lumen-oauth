package dcr

import (
	"context"
	"testing"
	"time"

	"github.com/joey/lumen-oauth/internal/domain/client"
	"github.com/joey/lumen-oauth/internal/infrastructure/redirect"
)

type fakeClientRepo struct {
	saved client.OAuthClient
}

func (f *fakeClientRepo) GetByID(context.Context, string) (client.OAuthClient, error) {
	return client.OAuthClient{}, nil
}

func (f *fakeClientRepo) Save(_ context.Context, in client.OAuthClient) error {
	f.saved = in
	return nil
}

type fakeID struct {
	values []string
}

func (f *fakeID) New() string {
	if len(f.values) == 0 {
		return "id"
	}
	v := f.values[0]
	f.values = f.values[1:]
	return v
}

type fakeClock struct {
	now time.Time
}

func (f fakeClock) Now() time.Time { return f.now }

func TestRegisterClient_PublicPKCEDCR(t *testing.T) {
	repo := &fakeClientRepo{}
	now := time.Unix(1760000000, 0).UTC()
	svc := Service{
		Clients: repo,
		Redirects: redirect.Validator{Config: redirect.Config{
			LoopbackEnabled: true,
			LoopbackPaths:   []string{"/callback"},
		}},
		IDGen:             &fakeID{values: []string{"client", "reg"}},
		Clock:             fakeClock{now: now},
		Enabled:           true,
		Mode:              "guarded",
		SupportedScopes:   []string{"mcp:tools", "offline_access"},
		DefaultTrustLevel: "unknown_dcr",
	}

	out, err := svc.RegisterClient(context.Background(), "", client.OAuthClient{
		Name:                    "Claude Code",
		RedirectURIs:            []string{"http://localhost:3118/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
		Scopes:                  []string{"mcp:tools", "offline_access"},
	})
	if err != nil {
		t.Fatalf("RegisterClient() error = %v", err)
	}
	if out.ClientID != "dcr-client" || out.ClientSecret != "" {
		t.Fatalf("unexpected client credentials: %+v", out)
	}
	if out.ClientIDIssuedAt != now.Unix() {
		t.Fatalf("client_id_issued_at=%d want %d", out.ClientIDIssuedAt, now.Unix())
	}
	if len(out.RedirectURIs) != 1 || out.RedirectURIs[0] != "http://localhost:3118/callback" {
		t.Fatalf("redirect_uris=%#v", out.RedirectURIs)
	}
	if repo.saved.TokenEndpointAuthMethod != "none" || repo.saved.TrustLevel != "unknown_dcr" {
		t.Fatalf("saved client mismatch: %+v", repo.saved)
	}
}

func TestRegisterClient_RejectsUnsafeRedirect(t *testing.T) {
	repo := &fakeClientRepo{}
	svc := Service{
		Clients: repo,
		Redirects: redirect.Validator{Config: redirect.Config{
			LoopbackEnabled: true,
			LoopbackPaths:   []string{"/callback"},
		}},
		Enabled: true,
		Mode:    "guarded",
	}

	_, err := svc.RegisterClient(context.Background(), "", client.OAuthClient{
		Name:                    "Unsafe",
		RedirectURIs:            []string{"https://example.com/callback#token"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "none",
	})
	if err != ErrInvalidClient {
		t.Fatalf("err=%v want ErrInvalidClient", err)
	}
}
