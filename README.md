# Lumen OAuth

OAuth 2.0 / OpenID Connect authorization server, built with pure Go standard library (no framework). Supports authorization code flow with PKCE, dynamic client registration (DCR), refresh token rotation, session management, user registration with email verification, RBAC, and invite-based onboarding.

## Features

- **OAuth 2.0 Authorization Code + PKCE** (S256)
- **OpenID Connect Discovery** (`/.well-known/openid-configuration`)
- **OAuth Authorization Server Metadata** (`/.well-known/oauth-authorization-server`)
- **Dynamic Client Registration** (RFC 7591, with optional IAT guard)
- **Refresh Token Rotation** with reuse detection
- **Client Credentials Grant** for service-to-service auth
- **Session Management** with CSRF protection
- **User Registration** with email verification (6-digit code)
- **Invite System** for controlled user onboarding
- **RBAC** (role-based access control, optional)
- **Bootstrap Admin** auto-created on first start
- **Embedded Login & Consent Pages** for browser-based OAuth flows
- **Hexagonal Architecture** (domain / application / infrastructure / interfaces)

## Quick Start

```bash
# Run locally
go run ./cmd/lumen-oauth --config configs/config.yaml

# Or via Docker Compose (from project root)
docker compose up -d oauth
```

Default admin account: `admin@example.com` / `admin`

## API Endpoints

### OAuth / OIDC

| Method | Path | Description |
|--------|------|-------------|
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/.well-known/oauth-authorization-server` | OAuth AS metadata |
| GET | `/.well-known/jwks.json` | Public JWKS |
| GET | `/oauth/authorize` | Authorization endpoint (redirects) |
| POST | `/oauth/token` | Token endpoint (code exchange, refresh, client_credentials) |
| POST | `/oauth/register` | Dynamic Client Registration |
| POST | `/oauth/consent` | Grant consent for a client |
| GET | `/oauth/consent/request` | Get consent details |

### Auth

| Method | Path | Description |
|--------|------|-------------|
| POST | `/auth/login` | Email + password login, returns access token + session |
| POST | `/auth/logout` | Revoke session |
| GET | `/auth/me` | Current user info (bearer token) |
| POST | `/auth/register` | User self-registration (sends verification code) |
| POST | `/auth/verify-email` | Verify email with 6-digit code |
| POST | `/auth/invitations` | Create invite (admin) |
| POST | `/auth/register/accept` | Accept invite |

### Pages (HTML)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/login` | Browser login page for OAuth flows |
| GET | `/consent` | Browser consent page for OAuth flows |

### Admin

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/roles` | List roles |
| POST | `/admin/roles` | Create/update role |
| POST | `/admin/role-bindings` | Bind role to subject |

## Configuration

```yaml
server:
  http_listen: ":9080"

oauth:
  issuer: http://localhost:9080
  audience: [lumen-mcp]
  signing_key: your-secret-key
  access_token_ttl: 15m

bootstrap_admin:
  enabled: true
  email: admin@example.com
  password: admin

dcr:
  mode: open              # open | guarded | iat_required | disabled
  allowed_redirects:
    loopback_enabled: true

registration:
  enabled: true

storage:
  driver: postgres        # postgres | sqlite
  postgres_url: postgres://user:pass@host:5432/db?sslmode=disable
```

When SMTP is not configured, email verification uses a fixed code: `111111`.

## Architecture

```
cmd/lumen-oauth/              Entry point
internal/
  domain/                     Pure domain models (no dependencies)
    user/                     User aggregate
    client/                   OAuth client
    authcode/                 Authorization code
    grant/                    Consent grant
    refreshtoken/             Refresh token
    session/                  Login session
    verification/             Email verification
    token/                    Access token value object
    invite/                   Invite
    role/                     RBAC role
  application/                Use cases (ports + services)
    auth/                     Login, authorize, token exchange, consent
    dcr/                      Dynamic client registration
    registration/             User self-registration + verification
    invite/                   Invite management
    rbac/                     Role management
    audit/                    Audit events
    ports/                    Interface definitions
  infrastructure/             Adapters
    jwt/                      HMAC-SHA256 JWT signer + verifier
    jwks/                     JWKS provider
    password/                 PBKDF2-SHA256 hasher
    redirect/                 Redirect URI validator
    sqlite/                   PostgreSQL + SQLite repositories
    email/                    SMTP + console email sender
    clock/                    System clock
    idgen/                    Random ID generator
  interfaces/http/            HTTP layer
    handlers/                 Request handlers
    middleware/                CORS, request ID, recovery, metrics, etc.
    routes/                   Router composition
  platform/                   Cross-cutting (logging, observability)
  bootstrap/                  App wiring
```
