package dcr

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
	"github.com/joey/lumen-oauth/internal/domain/client"
)

var (
	ErrUnauthorizedIAT = errors.New("missing or invalid initial access token")
	ErrInvalidClient   = errors.New("invalid client registration request")
	ErrDCRDisabled     = errors.New("dynamic client registration is disabled")
)

type Service struct {
	Clients             ports.ClientRepository
	Redirects           ports.RedirectURIValidator
	IDGen               ports.IDGenerator
	AuditSink           ports.AuditSink
	Clock               ports.Clock
	Enabled             bool
	Mode                string
	IATRequired         bool
	InitialAccessTokens []string
	SupportedScopes     []string
	DefaultTrustLevel   string
}

type RegisterResult struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope,omitempty"`
	TrustLevel              string   `json:"trust_level,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token"`
}

func (s Service) RegisterClient(ctx context.Context, iat string, in client.OAuthClient) (RegisterResult, error) {
	if !s.dcrEnabled() {
		return RegisterResult{}, ErrDCRDisabled
	}
	if s.requiresIAT() && !s.validIAT(iat) {
		return RegisterResult{}, ErrUnauthorizedIAT
	}

	grantTypes := normalizeGrantTypes(in.GrantTypes)
	if len(grantTypes) == 0 {
		grantTypes = []string{"client_credentials"}
	}
	if !validGrantTypes(grantTypes) {
		return RegisterResult{}, ErrInvalidClient
	}
	responseTypes := normalizeResponseTypes(in.ResponseTypes, grantTypes)
	if !validResponseTypes(responseTypes) {
		return RegisterResult{}, ErrInvalidClient
	}
	tokenEndpointAuthMethod := strings.TrimSpace(in.TokenEndpointAuthMethod)
	if tokenEndpointAuthMethod == "" {
		tokenEndpointAuthMethod = "client_secret_post"
	}
	if tokenEndpointAuthMethod != "none" && tokenEndpointAuthMethod != "client_secret_post" {
		return RegisterResult{}, ErrInvalidClient
	}
	redirectURIs, err := s.validateRedirectURIs(ctx, in.RedirectURIs)
	if err != nil {
		return RegisterResult{}, err
	}
	if slices.Contains(grantTypes, "authorization_code") && len(redirectURIs) == 0 {
		return RegisterResult{}, ErrInvalidClient
	}

	clientID := strings.TrimSpace(in.ID)
	if clientID == "" {
		clientID = "dcr-client"
		if s.IDGen != nil {
			clientID = "dcr-" + s.IDGen.New()
		}
	}
	if strings.TrimSpace(in.Name) == "" {
		in.Name = "Dynamic Client " + clientID
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock.Now().UTC()
	}
	clientSecret := ""
	if tokenEndpointAuthMethod != "none" {
		clientSecret = "sec-local-dev"
		if s.IDGen != nil {
			clientSecret = "sec-" + s.IDGen.New()
		}
		in.ClientSecretSHA256 = hashSecretSHA256(clientSecret)
	}
	in.ID = clientID
	in.GrantTypes = grantTypes
	in.ResponseTypes = responseTypes
	in.RedirectURIs = redirectURIs
	in.Scopes = normalizeScopesAgainst(in.Scopes, s.SupportedScopes)
	in.TokenEndpointAuthMethod = tokenEndpointAuthMethod
	in.TrustLevel = strings.TrimSpace(in.TrustLevel)
	if in.TrustLevel == "" {
		in.TrustLevel = s.defaultTrustLevel()
	}
	in.ClientIDIssuedAt = now.Unix()
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
		ClientSecretExpiresAt:   in.ClientSecretExpiresAt,
		ClientIDIssuedAt:        in.ClientIDIssuedAt,
		RedirectURIs:            redirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		Scope:                   scopeJoined,
		TrustLevel:              in.TrustLevel,
		RegistrationAccessToken: registrationToken,
	}, nil
}

func (s Service) validateRedirectURIs(ctx context.Context, in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if s.Redirects == nil {
		return nil, ErrInvalidClient
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		normalized, err := s.Redirects.Validate(ctx, raw)
		if err != nil {
			return nil, ErrInvalidClient
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	slices.Sort(out)
	return out, nil
}

func (s Service) dcrEnabled() bool {
	mode := strings.TrimSpace(s.Mode)
	if mode == "disabled" {
		return false
	}
	return true
}

func (s Service) requiresIAT() bool {
	return s.IATRequired || strings.TrimSpace(s.Mode) == "iat_required"
}

func (s Service) defaultTrustLevel() string {
	if strings.TrimSpace(s.DefaultTrustLevel) == "" {
		return "unknown_dcr"
	}
	return strings.TrimSpace(s.DefaultTrustLevel)
}

func (s Service) validIAT(in string) bool {
	in = strings.TrimSpace(strings.TrimPrefix(in, "Bearer "))
	if in == "" {
		return false
	}
	inHash := sha256.Sum256([]byte(in))
	for _, candidate := range s.InitialAccessTokens {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		candidateHash := sha256.Sum256([]byte(candidate))
		if subtle.ConstantTimeCompare(inHash[:], candidateHash[:]) == 1 {
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

func normalizeResponseTypes(in []string, grantTypes []string) []string {
	if len(in) == 0 && slices.Contains(grantTypes, "authorization_code") {
		return []string{"code"}
	}
	if len(in) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		set[v] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

func validGrantTypes(in []string) bool {
	for _, v := range in {
		switch v {
		case "authorization_code", "refresh_token", "client_credentials":
		default:
			return false
		}
	}
	return true
}

func validResponseTypes(in []string) bool {
	for _, v := range in {
		if v != "code" {
			return false
		}
	}
	return true
}

func normalizeScopesAgainst(in, supported []string) []string {
	supportedSet := make(map[string]struct{}, len(supported))
	for _, scope := range supported {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			supportedSet[scope] = struct{}{}
		}
	}
	if len(in) == 0 {
		out := make([]string, 0, len(supportedSet))
		for scope := range supportedSet {
			out = append(out, scope)
		}
		slices.Sort(out)
		return out
	}
	set := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if len(supportedSet) > 0 {
			if _, ok := supportedSet[s]; !ok {
				continue
			}
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
