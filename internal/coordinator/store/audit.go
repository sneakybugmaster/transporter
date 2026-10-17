package store

import (
	"context"
	"time"
)

// AuditEntry records an administrative change.
type AuditEntry struct {
	ID int64
	// Time is set by AppendAudit.
	Time time.Time
	// Actor is the admin's username, or e.g. "cli" or "policy".
	Actor  string
	Action string
	Target string
	Detail string
}

// AppendAudit adds an entry to the audit log.
func (s *Store) AppendAudit(ctx context.Context, e AuditEntry) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit_log (time, actor, action, target, detail) VALUES (?, ?, ?, ?, ?)`,
		s.now().Unix(), e.Actor, e.Action, e.Target, e.Detail)
	return err
}

// ListAudit returns up to limit entries older than before (all when before
// is 0), newest first.
func (s *Store) ListAudit(ctx context.Context, limit int, before int64) ([]AuditEntry, error) {
	if before <= 0 {
		before = 1<<63 - 1
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, time, actor, action, target, detail FROM audit_log WHERE id < ? ORDER BY id DESC LIMIT ?`, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var (
			e  AuditEntry
			ts int64
		)
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.Target, &e.Detail); err != nil {
			return nil, err
		}
		e.Time = time.Unix(ts, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}
