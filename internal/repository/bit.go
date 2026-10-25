package repository

import (
	"fmt"

	"github.com/bravo68web/atrium/internal/telemetry"
	// bit scans an INTEGER 0/1 column. SQLite may return a bool and Postgres an int64.
)

type bit int

func (b *bit) Scan(src any) error {
	defer telemetry.Step("repository.bit.Scan")()
	switch v := src.(type) {
	case bool:
		if v {
			*b = 1
		} else {
			*b = 0
		}
	case int64:
		*b = bit(v)
	case int32:
		*b = bit(v)
	case int:
		*b = bit(v)
	case []byte:
		if string(v) == "1" || string(v) == "t" || string(v) == "true" {
			*b = 1
		} else {
			*b = 0
		}
	case string:
		if v == "1" || v == "t" || v == "true" {
			*b = 1
		} else {
			*b = 0
		}
	case nil:
		*b = 0
	default:
		return fmt.Errorf("cannot scan %T into bit", src)
	}
	return nil
}

func (b bit) Bool() bool { defer telemetry.Step("repository.bit.Bool")(); return b != 0 }
