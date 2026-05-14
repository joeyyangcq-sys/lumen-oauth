package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/joey/lumen-oauth/internal/application/ports"
	"github.com/joey/lumen-oauth/internal/domain/authcode"
	"github.com/joey/lumen-oauth/internal/domain/client"
	"github.com/joey/lumen-oauth/internal/domain/grant"
	"github.com/joey/lumen-oauth/internal/domain/invite"
	"github.com/joey/lumen-oauth/internal/domain/refreshtoken"
	"github.com/joey/lumen-oauth/internal/domain/role"
	"github.com/joey/lumen-oauth/internal/domain/user"
)

var (
	ErrNotImplemented = errors.New("sqlite repository method not implemented")
)

type Repositories struct {
	DB *sql.DB
}

func OpenAndInit(path string) (Repositories, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return Repositories{}, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return Repositories{}, err
	}
	repos := Repositories{DB: db}
	if err := repos.initSchema(context.Background()); err != nil {
		_ = db.Close()
		return Repositories{}, err
	}
	if err := repos.seedLocalDevData(context.Background()); err != nil {
		_ = db.Close()
		return Repositories{}, err
	}
	return repos, nil
}

func (r Repositories) Close() error {
	if r.DB == nil {
		return nil
	}
	return r.DB.Close()
}

func (r Repositories) initSchema(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS oauth_clients (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			secret_sha256 TEXT NOT NULL,
			redirect_uris TEXT NOT NULL DEFAULT '',
			grant_types TEXT NOT NULL DEFAULT '',
			response_types TEXT NOT NULL DEFAULT '',
			scopes TEXT NOT NULL DEFAULT '',
			token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_post',
			trust_level TEXT NOT NULL DEFAULT 'unknown_dcr',
			client_id_issued_at INTEGER NOT NULL DEFAULT 0,
			client_secret_expires_at INTEGER NOT NULL DEFAULT 0,
			blocked_at TIMESTAMP NULL,
			disabled INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL,
			is_admin INTEGER NOT NULL DEFAULT 0,
			disabled INTEGER NOT NULL DEFAULT 0,
			force_change_password INTEGER NOT NULL DEFAULT 0,
			last_login_at TIMESTAMP NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
			id TEXT PRIMARY KEY,
			code_hash TEXT NOT NULL UNIQUE,
			client_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			resource TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT '',
			code_challenge TEXT NOT NULL,
			code_challenge_method TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			used_at TIMESTAMP NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS oauth_grants (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			resource TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at TIMESTAMP NULL,
			UNIQUE(user_id, client_id, resource)
		);`,
		`CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
			id TEXT PRIMARY KEY,
			token_hash TEXT NOT NULL UNIQUE,
			grant_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			resource TEXT NOT NULL,
			scope TEXT NOT NULL DEFAULT '',
			expires_at TIMESTAMP NOT NULL,
			used_at TIMESTAMP NULL,
			revoked_at TIMESTAMP NULL,
			replaced_by_id TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS subject_roles (
			subject TEXT NOT NULL,
			role_name TEXT NOT NULL,
			PRIMARY KEY (subject, role_name)
		);`,
		`CREATE TABLE IF NOT EXISTS role_scopes (
			role_name TEXT NOT NULL,
			scope TEXT NOT NULL,
			PRIMARY KEY (role_name, scope)
		);`,
		`CREATE TABLE IF NOT EXISTS invitations (
			code TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			role_name TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			used_at TIMESTAMP NULL,
			revoked_at TIMESTAMP NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS oauth_audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			action TEXT NOT NULL,
			actor TEXT NOT NULL,
			client_id TEXT NOT NULL,
			result TEXT NOT NULL,
			trace_id TEXT NOT NULL,
			details_json TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMP NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := r.DB.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return r.ensureOAuthClientColumns(ctx)
}

func (r Repositories) ensureOAuthClientColumns(ctx context.Context) error {
	existing, err := r.tableColumns(ctx, "oauth_clients")
	if err != nil {
		return err
	}
	columns := map[string]string{
		"redirect_uris":              "ALTER TABLE oauth_clients ADD COLUMN redirect_uris TEXT NOT NULL DEFAULT ''",
		"response_types":             "ALTER TABLE oauth_clients ADD COLUMN response_types TEXT NOT NULL DEFAULT ''",
		"token_endpoint_auth_method": "ALTER TABLE oauth_clients ADD COLUMN token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_post'",
		"trust_level":                "ALTER TABLE oauth_clients ADD COLUMN trust_level TEXT NOT NULL DEFAULT 'unknown_dcr'",
		"client_id_issued_at":        "ALTER TABLE oauth_clients ADD COLUMN client_id_issued_at INTEGER NOT NULL DEFAULT 0",
		"client_secret_expires_at":   "ALTER TABLE oauth_clients ADD COLUMN client_secret_expires_at INTEGER NOT NULL DEFAULT 0",
		"blocked_at":                 "ALTER TABLE oauth_clients ADD COLUMN blocked_at TIMESTAMP NULL",
	}
	for name, stmt := range columns {
		if existing[name] {
			continue
		}
		if _, err := r.DB.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func (r Repositories) tableColumns(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := r.DB.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make(map[string]bool)
	for rows.Next() {
		var (
			cid        int
			name       string
			columnType string
			notNull    int
			defaultVal sql.NullString
			pk         int
		)
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
			return nil, err
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (r Repositories) seedLocalDevData(ctx context.Context) error {
	const defaultClientID = "local-dev-client"
	const defaultClientSecret = "local-dev-secret"
	const defaultRoleName = "local-dev-operator"

	clientSecretHash := hashSecretSHA256(defaultClientSecret)
	if _, err := r.DB.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO oauth_clients (id, name, secret_sha256, grant_types, scopes, disabled) VALUES (?, ?, ?, ?, ?, 0)`,
		defaultClientID,
		"Local Dev Client",
		clientSecretHash,
		"client_credentials",
		"routes:read,routes:write,services:read,services:write,upstreams:read,upstreams:write,admin:dangerous",
	); err != nil {
		return err
	}
	if _, err := r.DB.ExecContext(
		ctx,
		`INSERT OR IGNORE INTO subject_roles (subject, role_name) VALUES (?, ?)`,
		defaultClientID,
		defaultRoleName,
	); err != nil {
		return err
	}
	defaultScopes := []string{
		"routes:read", "routes:write",
		"services:read", "services:write",
		"upstreams:read", "upstreams:write",
		"plugins:read", "plugins:write",
		"global_rules:read", "global_rules:write",
		"gateway:bundle:apply", "gateway:history:rollback",
		"admin:dangerous",
	}
	for _, scope := range defaultScopes {
		if _, err := r.DB.ExecContext(
			ctx,
			`INSERT OR IGNORE INTO role_scopes (role_name, scope) VALUES (?, ?)`,
			defaultRoleName,
			scope,
		); err != nil {
			return err
		}
	}
	return nil
}

func (r Repositories) GetByID(ctx context.Context, clientID string) (client.OAuthClient, error) {
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, name, secret_sha256, redirect_uris, grant_types, response_types, scopes,
		       token_endpoint_auth_method, trust_level, client_id_issued_at, client_secret_expires_at, disabled
		FROM oauth_clients
		WHERE id = ?`, clientID)
	var (
		id                      string
		name                    string
		secretHash              string
		redirectURIs            string
		grantTypes              string
		responseTypes           string
		scopes                  string
		tokenEndpointAuthMethod string
		trustLevel              string
		clientIDIssuedAt        int64
		clientSecretExpiresAt   int64
		disabled                int
	)
	if err := row.Scan(
		&id,
		&name,
		&secretHash,
		&redirectURIs,
		&grantTypes,
		&responseTypes,
		&scopes,
		&tokenEndpointAuthMethod,
		&trustLevel,
		&clientIDIssuedAt,
		&clientSecretExpiresAt,
		&disabled,
	); err != nil {
		return client.OAuthClient{}, err
	}
	return client.OAuthClient{
		ID:                      id,
		Name:                    name,
		ClientSecretSHA256:      secretHash,
		RedirectURIs:            splitCommaList(redirectURIs),
		GrantTypes:              splitCommaList(grantTypes),
		ResponseTypes:           splitCommaList(responseTypes),
		Scopes:                  splitCommaList(scopes),
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		TrustLevel:              trustLevel,
		ClientIDIssuedAt:        clientIDIssuedAt,
		ClientSecretExpiresAt:   clientSecretExpiresAt,
		Disabled:                disabled == 1,
	}, nil
}

func (r Repositories) Save(ctx context.Context, in client.OAuthClient) error {
	if strings.TrimSpace(in.ID) == "" {
		return errors.New("client id cannot be empty")
	}
	if strings.TrimSpace(in.ClientSecretSHA256) == "" && strings.TrimSpace(in.TokenEndpointAuthMethod) != "none" {
		return errors.New("client secret hash cannot be empty")
	}
	_, err := r.DB.ExecContext(ctx, `
		INSERT INTO oauth_clients (
			id, name, secret_sha256, redirect_uris, grant_types, response_types, scopes,
			token_endpoint_auth_method, trust_level, client_id_issued_at, client_secret_expires_at,
			disabled, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			secret_sha256 = excluded.secret_sha256,
			redirect_uris = excluded.redirect_uris,
			grant_types = excluded.grant_types,
			response_types = excluded.response_types,
			scopes = excluded.scopes,
			token_endpoint_auth_method = excluded.token_endpoint_auth_method,
			trust_level = excluded.trust_level,
			client_id_issued_at = excluded.client_id_issued_at,
			client_secret_expires_at = excluded.client_secret_expires_at,
			disabled = excluded.disabled,
			updated_at = CURRENT_TIMESTAMP`,
		in.ID,
		in.Name,
		in.ClientSecretSHA256,
		strings.Join(in.RedirectURIs, ","),
		strings.Join(in.GrantTypes, ","),
		strings.Join(in.ResponseTypes, ","),
		strings.Join(in.Scopes, ","),
		defaultString(in.TokenEndpointAuthMethod, "client_secret_post"),
		defaultString(in.TrustLevel, "unknown_dcr"),
		in.ClientIDIssuedAt,
		in.ClientSecretExpiresAt,
		boolToInt(in.Disabled),
	)
	return err
}

func (r Repositories) GetUserByID(ctx context.Context, id string) (user.User, error) {
	return r.getUser(ctx, `id = ?`, id)
}

func (r Repositories) GetUserByEmail(ctx context.Context, email string) (user.User, error) {
	return r.getUser(ctx, `lower(email) = lower(?)`, email)
}

func (r Repositories) getUser(ctx context.Context, where string, arg string) (user.User, error) {
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, email, name, password_hash, is_admin, disabled, force_change_password,
		       last_login_at, created_at, updated_at
		FROM users
		WHERE `+where, arg)
	var (
		out                 user.User
		isAdmin             int
		disabled            int
		forceChangePassword int
		lastLoginAt         sql.NullTime
		createdAt           time.Time
		updatedAt           time.Time
	)
	if err := row.Scan(
		&out.ID,
		&out.Email,
		&out.Name,
		&out.PasswordHash,
		&isAdmin,
		&disabled,
		&forceChangePassword,
		&lastLoginAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return user.User{}, err
	}
	out.IsAdmin = isAdmin == 1
	out.Disabled = disabled == 1
	out.ForceChangePassword = forceChangePassword == 1
	if lastLoginAt.Valid {
		t := lastLoginAt.Time.UTC()
		out.LastLoginAt = &t
	}
	out.CreatedAt = createdAt.UTC()
	out.UpdatedAt = updatedAt.UTC()
	return out, nil
}

func (r Repositories) SaveUser(ctx context.Context, in user.User) error {
	if strings.TrimSpace(in.ID) == "" {
		return errors.New("user id cannot be empty")
	}
	if strings.TrimSpace(in.Email) == "" {
		return errors.New("user email cannot be empty")
	}
	if strings.TrimSpace(in.PasswordHash) == "" {
		return errors.New("user password hash cannot be empty")
	}
	_, err := r.DB.ExecContext(ctx, `
		INSERT INTO users (
			id, email, name, password_hash, is_admin, disabled, force_change_password, updated_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			email = excluded.email,
			name = excluded.name,
			password_hash = excluded.password_hash,
			is_admin = excluded.is_admin,
			disabled = excluded.disabled,
			force_change_password = excluded.force_change_password,
			updated_at = CURRENT_TIMESTAMP`,
		in.ID,
		strings.TrimSpace(strings.ToLower(in.Email)),
		in.Name,
		in.PasswordHash,
		boolToInt(in.IsAdmin),
		boolToInt(in.Disabled),
		boolToInt(in.ForceChangePassword),
	)
	return err
}

func (r Repositories) UpdateUserLastLogin(ctx context.Context, id string, at time.Time) error {
	_, err := r.DB.ExecContext(ctx, `UPDATE users SET last_login_at = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, at.UTC(), id)
	return err
}

func (r Repositories) SaveAuthorizationCode(ctx context.Context, code authcode.AuthorizationCode) error {
	_, err := r.DB.ExecContext(ctx, `
		INSERT INTO oauth_authorization_codes (
			id, code_hash, client_id, user_id, redirect_uri, resource, scope,
			code_challenge, code_challenge_method, expires_at, used_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
		code.ID,
		code.CodeHash,
		code.ClientID,
		code.UserID,
		code.RedirectURI,
		code.Resource,
		strings.Join(code.Scopes, " "),
		code.CodeChallenge,
		code.CodeChallengeMethod,
		code.ExpiresAt.UTC(),
	)
	return err
}

func (r Repositories) GetAuthorizationCodeByHash(ctx context.Context, codeHash string) (authcode.AuthorizationCode, error) {
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, code_hash, client_id, user_id, redirect_uri, resource, scope,
		       code_challenge, code_challenge_method, expires_at, used_at, created_at
		FROM oauth_authorization_codes
		WHERE code_hash = ?`, codeHash)
	var (
		out       authcode.AuthorizationCode
		scope     string
		expiresAt time.Time
		usedAt    sql.NullTime
		createdAt time.Time
	)
	if err := row.Scan(
		&out.ID,
		&out.CodeHash,
		&out.ClientID,
		&out.UserID,
		&out.RedirectURI,
		&out.Resource,
		&scope,
		&out.CodeChallenge,
		&out.CodeChallengeMethod,
		&expiresAt,
		&usedAt,
		&createdAt,
	); err != nil {
		return authcode.AuthorizationCode{}, err
	}
	out.Scopes = strings.Fields(scope)
	out.ExpiresAt = expiresAt.UTC()
	out.CreatedAt = createdAt.UTC()
	if usedAt.Valid {
		t := usedAt.Time.UTC()
		out.UsedAt = &t
	}
	return out, nil
}

func (r Repositories) MarkAuthorizationCodeUsed(ctx context.Context, codeHash string, usedAt time.Time) error {
	res, err := r.DB.ExecContext(ctx, `UPDATE oauth_authorization_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL`, usedAt.UTC(), codeHash)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r Repositories) UpsertGrant(ctx context.Context, in grant.Grant) error {
	_, err := r.DB.ExecContext(ctx, `
		INSERT INTO oauth_grants (id, user_id, client_id, resource, scope, revoked_at)
		VALUES (?, ?, ?, ?, ?, NULL)
		ON CONFLICT(user_id, client_id, resource) DO UPDATE SET
			scope = excluded.scope,
			revoked_at = NULL`,
		in.ID,
		in.UserID,
		in.ClientID,
		in.Resource,
		strings.Join(in.Scopes, " "),
	)
	return err
}

func (r Repositories) GetActiveGrant(ctx context.Context, userID, clientID, resource string) (grant.Grant, error) {
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, user_id, client_id, resource, scope, created_at, revoked_at
		FROM oauth_grants
		WHERE user_id = ? AND client_id = ? AND resource = ? AND revoked_at IS NULL`,
		userID,
		clientID,
		resource,
	)
	var (
		out       grant.Grant
		scope     string
		createdAt time.Time
		revokedAt sql.NullTime
	)
	if err := row.Scan(&out.ID, &out.UserID, &out.ClientID, &out.Resource, &scope, &createdAt, &revokedAt); err != nil {
		return grant.Grant{}, err
	}
	out.Scopes = strings.Fields(scope)
	out.CreatedAt = createdAt.UTC()
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		out.RevokedAt = &t
	}
	return out, nil
}

func (r Repositories) SaveRefreshToken(ctx context.Context, token refreshtoken.RefreshToken) error {
	_, err := r.DB.ExecContext(ctx, `
		INSERT INTO oauth_refresh_tokens (
			id, token_hash, grant_id, client_id, user_id, resource, scope,
			expires_at, used_at, revoked_at, replaced_by_id
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)`,
		token.ID,
		token.TokenHash,
		token.GrantID,
		token.ClientID,
		token.UserID,
		token.Resource,
		strings.Join(token.Scopes, " "),
		token.ExpiresAt.UTC(),
		token.ReplacedByID,
	)
	return err
}

func (r Repositories) GetRefreshTokenByHash(ctx context.Context, tokenHash string) (refreshtoken.RefreshToken, error) {
	row := r.DB.QueryRowContext(ctx, `
		SELECT id, token_hash, grant_id, client_id, user_id, resource, scope,
		       expires_at, used_at, revoked_at, replaced_by_id, created_at
		FROM oauth_refresh_tokens
		WHERE token_hash = ?`, tokenHash)
	var (
		out       refreshtoken.RefreshToken
		scope     string
		expiresAt time.Time
		usedAt    sql.NullTime
		revokedAt sql.NullTime
		createdAt time.Time
	)
	if err := row.Scan(
		&out.ID,
		&out.TokenHash,
		&out.GrantID,
		&out.ClientID,
		&out.UserID,
		&out.Resource,
		&scope,
		&expiresAt,
		&usedAt,
		&revokedAt,
		&out.ReplacedByID,
		&createdAt,
	); err != nil {
		return refreshtoken.RefreshToken{}, err
	}
	out.Scopes = strings.Fields(scope)
	out.ExpiresAt = expiresAt.UTC()
	out.CreatedAt = createdAt.UTC()
	if usedAt.Valid {
		t := usedAt.Time.UTC()
		out.UsedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		out.RevokedAt = &t
	}
	return out, nil
}

func (r Repositories) RotateRefreshToken(ctx context.Context, oldHash string, next refreshtoken.RefreshToken, usedAt time.Time) error {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO oauth_refresh_tokens (
			id, token_hash, grant_id, client_id, user_id, resource, scope,
			expires_at, used_at, revoked_at, replaced_by_id
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, '')`,
		next.ID,
		next.TokenHash,
		next.GrantID,
		next.ClientID,
		next.UserID,
		next.Resource,
		strings.Join(next.Scopes, " "),
		next.ExpiresAt.UTC(),
	); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE oauth_refresh_tokens
		SET used_at = ?, replaced_by_id = ?
		WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL`,
		usedAt.UTC(),
		next.ID,
		oldHash,
	)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return tx.Commit()
}

func (r Repositories) RevokeRefreshTokensByGrant(ctx context.Context, grantID string, revokedAt time.Time) error {
	_, err := r.DB.ExecContext(ctx, `
		UPDATE oauth_refresh_tokens
		SET revoked_at = ?
		WHERE grant_id = ? AND revoked_at IS NULL`,
		revokedAt.UTC(),
		grantID,
	)
	return err
}

func (r Repositories) ListForSubject(ctx context.Context, subject string) ([]role.Role, error) {
	rows, err := r.DB.QueryContext(ctx, `
		SELECT sr.role_name, rs.scope
		FROM subject_roles sr
		LEFT JOIN role_scopes rs ON rs.role_name = sr.role_name
		WHERE sr.subject = ?
		ORDER BY sr.role_name ASC, rs.scope ASC`, subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roleScopes := make(map[string][]string)
	for rows.Next() {
		var roleName string
		var scope sql.NullString
		if err := rows.Scan(&roleName, &scope); err != nil {
			return nil, err
		}
		if _, ok := roleScopes[roleName]; !ok {
			roleScopes[roleName] = []string{}
		}
		if scope.Valid && strings.TrimSpace(scope.String) != "" {
			roleScopes[roleName] = append(roleScopes[roleName], scope.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return mapRoleScopes(roleScopes), nil
}

func (r Repositories) ListRoles(ctx context.Context) ([]role.Role, error) {
	rows, err := r.DB.QueryContext(ctx, `SELECT role_name, scope FROM role_scopes ORDER BY role_name ASC, scope ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	roleScopes := make(map[string][]string)
	for rows.Next() {
		var roleName string
		var scope string
		if err := rows.Scan(&roleName, &scope); err != nil {
			return nil, err
		}
		roleScopes[roleName] = append(roleScopes[roleName], scope)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return mapRoleScopes(roleScopes), nil
}

func (r Repositories) UpsertRoleScopes(ctx context.Context, roleName string, scopes []string) error {
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return errors.New("role name cannot be empty")
	}
	scopes = dedupeSorted(scopes)
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM role_scopes WHERE role_name = ?`, roleName); err != nil {
		return err
	}
	for _, scope := range scopes {
		if strings.TrimSpace(scope) == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO role_scopes (role_name, scope) VALUES (?, ?)`, roleName, scope); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r Repositories) BindRoleToSubject(ctx context.Context, subject, roleName string) error {
	subject = strings.TrimSpace(subject)
	roleName = strings.TrimSpace(roleName)
	if subject == "" || roleName == "" {
		return errors.New("subject and role name are required")
	}
	_, err := r.DB.ExecContext(ctx, `INSERT OR IGNORE INTO subject_roles (subject, role_name) VALUES (?, ?)`, subject, roleName)
	return err
}

func (r Repositories) Create(ctx context.Context, in invite.Invitation) error {
	_, err := r.DB.ExecContext(ctx, `
		INSERT INTO invitations (code, email, role_name, expires_at, used_at, revoked_at)
		VALUES (?, ?, ?, ?, NULL, NULL)`,
		in.Code,
		in.Email,
		in.Role,
		in.ExpiresAt.UTC(),
	)
	return err
}

func (r Repositories) GetByCode(ctx context.Context, code string) (invite.Invitation, error) {
	row := r.DB.QueryRowContext(ctx, `
		SELECT code, email, role_name, expires_at, used_at, revoked_at
		FROM invitations
		WHERE code = ?`, code)
	var (
		out       invite.Invitation
		expiresAt time.Time
		usedAt    sql.NullTime
		revokedAt sql.NullTime
	)
	if err := row.Scan(&out.Code, &out.Email, &out.Role, &expiresAt, &usedAt, &revokedAt); err != nil {
		return invite.Invitation{}, err
	}
	out.ExpiresAt = expiresAt.UTC()
	if usedAt.Valid {
		t := usedAt.Time.UTC()
		out.UsedAt = &t
	}
	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		out.RevokedAt = &t
	}
	return out, nil
}

func (r Repositories) MarkUsed(ctx context.Context, code string, usedAt time.Time) error {
	res, err := r.DB.ExecContext(ctx, `UPDATE invitations SET used_at = ? WHERE code = ? AND used_at IS NULL`, usedAt.UTC(), code)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r Repositories) Record(ctx context.Context, event ports.AuditEvent) error {
	detailsJSON, err := marshalDetails(event.Details)
	if err != nil {
		return err
	}
	_, err = r.DB.ExecContext(ctx, `
		INSERT INTO oauth_audit_log (action, actor, client_id, result, trace_id, details_json, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.Action,
		event.Actor,
		event.ClientID,
		event.Result,
		event.TraceID,
		detailsJSON,
		event.Timestamp.UTC(),
	)
	return err
}

func hashSecretSHA256(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func splitCommaList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return dedupeSorted(out)
}

func mapRoleScopes(roleScopes map[string][]string) []role.Role {
	if len(roleScopes) == 0 {
		return []role.Role{}
	}
	names := make([]string, 0, len(roleScopes))
	for name := range roleScopes {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]role.Role, 0, len(names))
	for _, name := range names {
		out = append(out, role.Role{Name: name, Scopes: dedupeSorted(roleScopes[name])})
	}
	return out
}

func dedupeSorted(values []string) []string {
	if len(values) == 0 {
		return values
	}
	sort.Strings(values)
	out := make([]string, 0, len(values))
	last := ""
	for _, v := range values {
		if v == last {
			continue
		}
		last = v
		out = append(out, v)
	}
	return out
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func marshalDetails(details map[string]any) (string, error) {
	if details == nil {
		return "{}", nil
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
