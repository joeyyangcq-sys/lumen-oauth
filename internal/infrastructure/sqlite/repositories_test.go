package sqlite

import "testing"

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
