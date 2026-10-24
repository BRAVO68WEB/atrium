package repository

import (
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

// dbTime scans a timestamp that SQLite returns as text and Postgres returns as time.Time.
type dbTime struct {
	Time time.Time
}

func (t *dbTime) Scan(src any) error {
	defer telemetry.Step("repository.dbTime.Scan")()
	switch v := src.(type) {
	case time.Time:
		t.Time = v
		return nil
	case string:
		parsed, err := parseDBTime(v)
		if err != nil {
			return err
		}
		t.Time = parsed
		return nil
	case []byte:
		parsed, err := parseDBTime(string(v))
		if err != nil {
			return err
		}
		t.Time = parsed
		return nil
	case nil:
		t.Time = time.Time{}
		return nil
	default:
		return fmt.Errorf("cannot scan %T into time", src)
	}
}

func parseDBTime(value string) (time.Time, error) {
	defer telemetry.Step("repository.parseDBTime")()
	if i := strings.Index(value, " m="); i >= 0 {
		value = value[:i]
	}
	layouts := []string{
		"2006-01-02 15:04:05.999999999 -0700 MST",
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("parse time %q", value)
}
