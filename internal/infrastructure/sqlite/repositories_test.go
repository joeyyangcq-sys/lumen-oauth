package sqlite

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/joey/lumen-oauth/internal/domain/authcode"
	"github.com/joey/lumen-oauth/internal/domain/refreshtoken"
	"github.com/joey/lumen-oauth/internal/domain/user"
	"github.com/joey/lumen-oauth/internal/domain/verification"
)

func TestRebindUsesPostgresPlaceholders(t *testing.T) {
	repos := Repositories{driver: driverPostgres}
	got := repos.rebind("SELECT * FROM users WHERE id = ? AND email = lower(?)")
	want := "SELECT * FROM users WHERE id = $1 AND email = lower($2)"
	if got != want {
		t.Fatalf("rebind=%q, want %q", got, want)
	}
}

func TestRebindKeepsSQLitePlaceholders(t *testing.T) {
	repos := Repositories{driver: driverSQLite}
	got := repos.rebind("SELECT * FROM users WHERE id = ?")
	want := "SELECT * FROM users WHERE id = ?"
	if got != want {
		t.Fatalf("rebind=%q, want %q", got, want)
	}
}

func TestStringListRoundTripSupportsCommaInValues(t *testing.T) {
	values := []string{
		"https://example.com/callback?prompt=a,b",
		"http://localhost:3118/callback",
	}

	encoded := mustMarshalStringList(values)
	got := splitStringList(encoded)

	if len(got) != len(values) {
		t.Fatalf("len=%d, want %d: %#v", len(got), len(values), got)
	}
	for i := range values {
		if got[i] != values[i] {
			t.Fatalf("got[%d]=%q, want %q; encoded=%s", i, got[i], values[i], encoded)
		}
	}
}

func TestStringListReadsLegacyCommaFormat(t *testing.T) {
	got := splitStringList("routes:write,routes:read,routes:read")
	want := []string{"routes:read", "routes:write"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

func TestMarkEmailVerifiedAndSaveUserIsAtomicOnUserFailure(t *testing.T) {
	repos, err := OpenAndInit(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer repos.Close()

	now := time.Unix(1710000000, 0).UTC()
	if err := repos.SaveUser(t.Context(), user.User{
		ID:           "usr-existing",
		Email:        "taken@example.com",
		PasswordHash: "hash",
	}); err != nil {
		t.Fatalf("save existing user: %v", err)
	}
	v := verification.EmailVerification{
		ID:        "ev-1",
		Email:     "new@example.com",
		Code:      "123456",
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
	}
	if err := repos.SaveEmailVerification(t.Context(), v, "hash", "New User"); err != nil {
		t.Fatalf("save verification: %v", err)
	}

	err = repos.MarkEmailVerifiedAndSaveUser(t.Context(), v.ID, now, user.User{
		ID:           "usr-new",
		Email:        "taken@example.com",
		PasswordHash: "hash",
	})
	if err == nil {
		t.Fatal("expected duplicate email error, got nil")
	}

	got, _, _, err := repos.GetPendingByEmailAndCode(t.Context(), v.Email, v.Code)
	if err != nil {
		t.Fatalf("verification should remain pending after failed user save: %v", err)
	}
	if got.VerifiedAt != nil {
		t.Fatalf("verified_at=%v, want nil", got.VerifiedAt)
	}
}

func TestMarkEmailVerifiedAndSaveUserRejectsAlreadyVerified(t *testing.T) {
	repos, err := OpenAndInit(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer repos.Close()

	now := time.Unix(1710000000, 0).UTC()
	v := verification.EmailVerification{
		ID:        "ev-1",
		Email:     "new@example.com",
		Code:      "123456",
		ExpiresAt: now.Add(time.Minute),
		CreatedAt: now,
	}
	if err := repos.SaveEmailVerification(t.Context(), v, "hash", "New User"); err != nil {
		t.Fatalf("save verification: %v", err)
	}
	if err := repos.MarkEmailVerifiedAndSaveUser(t.Context(), v.ID, now, user.User{
		ID:           "usr-new",
		Email:        v.Email,
		PasswordHash: "hash",
	}); err != nil {
		t.Fatalf("verify and save user: %v", err)
	}

	err = repos.MarkEmailVerifiedAndSaveUser(t.Context(), v.ID, now, user.User{
		ID:           "usr-again",
		Email:        "again@example.com",
		PasswordHash: "hash",
	})
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err=%v, want sql.ErrNoRows", err)
	}
}

func TestMarkAuthorizationCodeUsedAndSaveRefreshTokenIsAtomicOnRefreshFailure(t *testing.T) {
	repos, err := OpenAndInit(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer repos.Close()

	now := time.Unix(1710000000, 0).UTC()
	code := authcode.AuthorizationCode{
		ID:                  "ac-1",
		CodeHash:            "code-hash",
		ClientID:            "client-1",
		UserID:              "user-1",
		RedirectURI:         "http://localhost/callback",
		Resource:            "aud",
		Scopes:              []string{"offline_access"},
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(time.Minute),
		CreatedAt:           now,
	}
	if err := repos.SaveAuthorizationCode(t.Context(), code); err != nil {
		t.Fatalf("save authorization code: %v", err)
	}
	existing := refreshtoken.RefreshToken{
		ID:        "rt-existing",
		TokenHash: "duplicate-hash",
		GrantID:   "grant-1",
		ClientID:  "client-1",
		UserID:    "user-1",
		Resource:  "aud",
		Scopes:    []string{"offline_access"},
		ExpiresAt: now.Add(time.Hour),
	}
	if err := repos.SaveRefreshToken(t.Context(), existing); err != nil {
		t.Fatalf("save existing refresh token: %v", err)
	}

	next := existing
	next.ID = "rt-next"
	err = repos.MarkAuthorizationCodeUsedAndSaveRefreshToken(t.Context(), code.CodeHash, now, &next)
	if err == nil {
		t.Fatal("expected duplicate refresh token error, got nil")
	}

	got, err := repos.GetAuthorizationCodeByHash(t.Context(), code.CodeHash)
	if err != nil {
		t.Fatalf("get authorization code: %v", err)
	}
	if got.UsedAt != nil {
		t.Fatalf("used_at=%v, want nil after refresh save failure", got.UsedAt)
	}
}

func TestMarkAuthorizationCodeUsedAndSaveRefreshTokenRejectsUsedCode(t *testing.T) {
	repos, err := OpenAndInit(filepath.Join(t.TempDir(), "oauth.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer repos.Close()

	now := time.Unix(1710000000, 0).UTC()
	code := authcode.AuthorizationCode{
		ID:                  "ac-1",
		CodeHash:            "code-hash",
		ClientID:            "client-1",
		UserID:              "user-1",
		RedirectURI:         "http://localhost/callback",
		Resource:            "aud",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		ExpiresAt:           now.Add(time.Minute),
		CreatedAt:           now,
	}
	if err := repos.SaveAuthorizationCode(t.Context(), code); err != nil {
		t.Fatalf("save authorization code: %v", err)
	}
	if err := repos.MarkAuthorizationCodeUsedAndSaveRefreshToken(t.Context(), code.CodeHash, now, nil); err != nil {
		t.Fatalf("mark used: %v", err)
	}

	err = repos.MarkAuthorizationCodeUsedAndSaveRefreshToken(t.Context(), code.CodeHash, now, nil)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("err=%v, want sql.ErrNoRows", err)
	}
}
