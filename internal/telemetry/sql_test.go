package telemetry

import "testing"

func TestRedactSQLDropsLiterals(t *testing.T) {
	got := redactSQL("SELECT id\nFROM users WHERE name = 'Ada Lovelace' AND n = ?")
	if got != "SELECT id FROM users WHERE name = '?' AND n = ?" {
		t.Fatalf("statement = %q", got)
	}
	if sqlOperation("  INSERT INTO t VALUES (?)") != "insert" {
		t.Fatal("operation")
	}
}
