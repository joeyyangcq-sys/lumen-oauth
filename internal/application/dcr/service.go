package dcr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"

	"github.com/joey/lumen-oauth/internal/application/ports"
	"github.com/joey/lumen-oauth/internal/domain/client"
)

var (
	ErrUnauthorizedIAT = errors.New("missing or invalid initial access token")
	ErrInvalidClient   = errors.New("invalid client registration request")
)

type Service struct {
	Clients             ports.ClientRepository
	IDGen               ports.IDGenerator
	AuditSink           ports.AuditSink
	IATRequired         bool
	InitialAccessTokens []string
}

type RegisterResult struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientSecret            string   `json:"client_secret"`
	GrantTypes              []string `json:"grant_types"`
	Scope                   string   `json:"scope,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token"`
}

func (s Service) RegisterClient(ctx context.Context, iat string, in client.OAuthClient) (RegisterResult, error) {
	if s.IATRequired && !s.validIAT(iat) {
		return RegisterResult{}, ErrUnauthorizedIAT
	}

	grantTypes := normalizeGrantTypes(in.GrantTypes)
	if len(grantTypes) == 0 {
		grantTypes = []string{"client_credentials"}
	}
	clientID := strings.TrimSpace(in.ID)
	if clientID == "" {
		clientID = "dcr-client"
		if s.IDGen != nil {
			clientID = "dcr-" + s.IDGen.New()
		}
	}
	clientSecret := "sec-local-dev"
	if s.IDGen != nil {
		clientSecret = "sec-" + s.IDGen.New()
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = "Dynamic Client " + clientID
	}
	in.ID = clientID
	in.GrantTypes = grantTypes
	in.ClientSecretSHA256 = hashSecretSHA256(clientSecret)
	in.Scopes = normalizeScopes(in.Scopes)
	in.Disabled = false
	if err := s.Clients.Save(ctx, in); err != nil {
		return RegisterResult{}, err
	}

	scopeJoined := strings.Join(in.Scopes, " ")
	registrationToken := "reg-local-dev"
	if s.IDGen != nil {
		registrationToken = "reg-" + s.IDGen.New()
	}
	return RegisterResult{
		ClientID:                clientID,
		ClientName:              in.Name,
		ClientSecret:            clientSecret,
		GrantTypes:              grantTypes,
		Scope:                   scopeJoined,
		RegistrationAccessToken: registrationToken,
	}, nil
}

func (s Service) validIAT(in string) bool {
	in = strings.TrimSpace(strings.TrimPrefix(in, "Bearer "))
	if in == "" {
		return false
	}
	for _, candidate := range s.InitialAccessTokens {
		if strings.TrimSpace(candidate) == in {
			return true
		}
	}
	return false
}

func normalizeGrantTypes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		set[g] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	slices.Sort(out)
	return out
}

func normalizeScopes(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func hashSecretSHA256(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}
