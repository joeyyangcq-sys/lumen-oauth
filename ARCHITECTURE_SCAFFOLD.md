# lumen-oauth Architecture Scaffold (Phase 0)

## Layering

- `cmd/`: process entry, signal handling, runtime wiring
- `internal/config`: config schema, defaults, validation, YAML loader
- `internal/domain`: pure models (`user`, `client`, `role`, `token`, `invite`)
- `internal/application`: use-cases (`auth`, `dcr`, `invite`, `rbac`, `audit`) + `ports`
- `internal/infrastructure`: adapters (`sqlite`, `jwt`, `jwks`, `clock`, `idgen`)
- `internal/interfaces/http`: handlers, middleware chain, route registration
- `internal/platform`: logging + observability primitives

Dependency direction: `interfaces -> application -> domain` and `infrastructure -> application -> domain`.

## Middleware Stack

Order:

1. RequestID
2. Recovery
3. AccessLog
4. Metrics (optional)

Current behavior:

- inject `X-Request-Id`
- panic-safe responses with stack logging
- structured access log (`method/path/status/duration_ms/trace_id`)
- expvar counters for requests/errors/latency

## Observability

- Logger: `slog` JSON/TEXT selectable via config
- Metrics: `expvar` scaffold for low-friction bootstrapping
- Built-in endpoints:
  - `/healthz`
  - `/debug/vars`

## TODO Hotspots

- `application/auth`: real client credential validation + scope derivation
- `application/dcr`: IAT verification + registration token lifecycle
- `application/invite`: invitation acceptance and user provisioning
- `infrastructure/jwt`: replace stub payload with signed JWS
- `infrastructure/sqlite`: full repositories + migrations
- `handlers/*`: bind request DTO validation + usecase execution
