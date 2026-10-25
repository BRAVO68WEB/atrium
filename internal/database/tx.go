package database

import (
	"database/sql"

	"github.com/bravo68web/atrium/internal/telemetry"
)

// WithTx runs fn in one transaction. The function must not use the outer
// database handle. SQLite allows one connection, so a second query waits
// forever while this transaction is open.
func (db *DB) WithTx(fn func(SQL) error) error {
	if db == nil || db.conn == nil {
		return sql.ErrConnDone
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	wrapped := &txSQL{tx: tx, db: db}
	if err := fn(wrapped); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

type txSQL struct {
	tx *sql.Tx
	db *DB
}

func (t *txSQL) Dialect() string { return t.db.Dialect() }

func (t *txSQL) Exec(query string, args ...any) (sql.Result, error) {
	done := telemetry.QuerySpan(t.db.driver, query, len(args))
	result, err := t.tx.Exec(t.db.prepare(query), args...)
	done(err)
	return result, err
}

func (t *txSQL) Query(query string, args ...any) (*sql.Rows, error) {
	done := telemetry.QuerySpan(t.db.driver, query, len(args))
	rows, err := t.tx.Query(t.db.prepare(query), args...)
	done(err)
	return rows, err
}

func (t *txSQL) QueryRow(query string, args ...any) Row {
	done := telemetry.QuerySpan(t.db.driver, query, len(args))
	row := &tracedRow{
		row:  t.tx.QueryRow(t.db.prepare(query), args...),
		done: done,
	}
	return row
}
