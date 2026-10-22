package version

import (
	"encoding/json"
	"testing"
)

func withBuild(t *testing.T, version, commit, date string) {
	t.Helper()
	prevVersion, prevCommit, prevDate := Version, Commit, Date
	Version, Commit, Date = version, commit, date
	t.Cleanup(func() {
		Version, Commit, Date = prevVersion, prevCommit, prevDate
	})
}

func TestCurrentOmitsEmptyBuildInfo(t *testing.T) {
	withBuild(t, "dev", "", "")
	body, err := json.Marshal(Current())
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"version":"dev"}` {
		t.Fatalf("body %s", body)
	}
	if Line() != "dev" {
		t.Fatalf("line %s", Line())
	}
}

func TestLineIncludesCommitAndDate(t *testing.T) {
	withBuild(t, "1.2.3", "abc123", "2026-10-22T00:00:00Z")
	if got := Line(); got != "1.2.3 (abc123, 2026-10-22T00:00:00Z)" {
		t.Fatalf("line %s", got)
	}
	body, err := json.Marshal(Current())
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"version":"1.2.3","commit":"abc123","date":"2026-10-22T00:00:00Z"}`
	if string(body) != want {
		t.Fatalf("body %s", body)
	}
}

func TestEmptyVersionFallsBackToDev(t *testing.T) {
	withBuild(t, "  ", "abc", "")
	if got := Line(); got != "dev (abc)" {
		t.Fatalf("line %s", got)
	}
}
