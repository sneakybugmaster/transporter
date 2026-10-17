package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// APITokenPrefix starts every API token.
const APITokenPrefix = "tpa_"

// APIToken lets scripts call the admin API as the admin who created it.
type APIToken struct {
	ID          string
	Description string
	AdminID     string
	Admin       string // username
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	LastUsed    *time.Time
}

// CreateAPIToken creates a token for adminID and returns it with its secret,
// which is not stored. A zero ttl never expires.
func (s *Store) CreateAPIToken(ctx context.Context, adminID, description string, ttl time.Duration) (APIToken, string, error) {
	now := s.now().UTC().Truncate(time.Second)
	t := APIToken{ID: newID(), Description: description, AdminID: adminID, CreatedAt: now}
	if ttl > 0 {
		exp := now.Add(ttl)
		t.ExpiresAt = &exp
	}
	secret := newSecret(APITokenPrefix)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO api_tokens (id, token_hash, description, admin_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
		t.ID, hashSecret(secret), t.Description, adminID, now.Unix(), unixOrNil(t.ExpiresAt))
	if err != nil {
		return APIToken{}, "", err
	}
	return t, secret, nil
}

// ListAPITokens returns all tokens, newest first.
func (s *Store) ListAPITokens(ctx context.Context) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT t.id, t.description, t.admin_id, a.username, t.created_at, t.expires_at, t.last_used
		 FROM api_tokens t JOIN admins a ON a.id = t.admin_id ORDER BY t.created_at DESC, t.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var (
			t                 APIToken
			created           int64
			expires, lastUsed sql.NullInt64
		)
		if err := rows.Scan(&t.ID, &t.Description, &t.AdminID, &t.Admin, &created, &expires, &lastUsed); err != nil {
			return nil, err
		}
		t.CreatedAt = time.Unix(created, 0).UTC()
		t.ExpiresAt, t.LastUsed = timePtr(expires), timePtr(lastUsed)
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeleteAPIToken revokes a token.
func (s *Store) DeleteAPIToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TokenAdmin returns the admin a valid token acts as, and the token's ID.
func (s *Store) TokenAdmin(ctx context.Context, secret string) (Admin, string, error) {
	var (
		a    Admin
		id   string
		at   int64
		used sql.NullInt64
		now  = s.now().UTC()
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT t.id, t.last_used, a.id, a.username, a.created_at, a.password_hash != '' FROM api_tokens t JOIN admins a ON a.id = t.admin_id
		 WHERE t.token_hash = ? AND (t.expires_at IS NULL OR t.expires_at > ?)`, hashSecret(secret), now.Unix(),
	).Scan(&id, &used, &a.ID, &a.Username, &at, &a.HasPassword)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, "", ErrNotFound
	}
	if err != nil {
		return Admin{}, "", err
	}
	a.CreatedAt = time.Unix(at, 0).UTC()
	if !used.Valid || now.Unix()-used.Int64 >= 60 { // at most one write a minute per token
		if _, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used = ? WHERE id = ?`, now.Unix(), id); err != nil {
			return Admin{}, "", err
		}
	}
	return a, id, nil
}

func timePtr(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.Unix(v.Int64, 0).UTC()
	return &t
}
