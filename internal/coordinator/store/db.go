package store

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
)

// dialect is the SQL flavour of the database behind a Store. Queries are
// written for SQLite with "?" placeholders and rewritten for Postgres.
type dialect int

const (
	sqliteDialect dialect = iota
	postgresDialect
)

// rebind rewrites "?" placeholders as $1, $2, ... for Postgres. Queries in
// this package never contain a literal question mark.
func (d dialect) rebind(q string) string {
	if d != postgresDialect || !strings.Contains(q, "?") {
		return q
	}
	var b strings.Builder
	n := 0
	for _, r := range q {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isUnique reports whether err is a unique-constraint violation.
func isUnique(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "duplicate key") || strings.Contains(msg, "23505")
}

// Advisory lock keys serialising transactions that read-then-write, which
// SQLite serialises by itself (one writer at a time).
const (
	lockAdmins = 4748
	lockNodes  = 4749
)

// serialize makes the transaction exclusive among those using the same key
// (Postgres only; until commit or rollback).
func (c txConn) serialize(ctx context.Context, key int) error {
	if c.d != postgresDialect {
		return nil
	}
	_, err := c.tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, key)
	return err
}

// conn runs queries on the database, rebinding them for its dialect.
type conn struct {
	db *sql.DB
	d  dialect
}

func (c conn) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return c.db.ExecContext(ctx, c.d.rebind(q), args...)
}

func (c conn) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return c.db.QueryContext(ctx, c.d.rebind(q), args...)
}

func (c conn) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return c.db.QueryRowContext(ctx, c.d.rebind(q), args...)
}

// txConn is conn for a transaction.
type txConn struct {
	tx *sql.Tx
	d  dialect
}

func (c txConn) ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return c.tx.ExecContext(ctx, c.d.rebind(q), args...)
}

func (c txConn) QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return c.tx.QueryContext(ctx, c.d.rebind(q), args...)
}

func (c txConn) QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row {
	return c.tx.QueryRowContext(ctx, c.d.rebind(q), args...)
}
