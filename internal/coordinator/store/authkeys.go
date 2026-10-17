package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AuthKeyPrefix starts every pre-auth key, making leaked keys easy to recognise.
const AuthKeyPrefix = "trk_"

// AuthKey is a pre-auth key used to enroll nodes. The secret itself is only
// returned once, at creation time.
type AuthKey struct {
	ID          string
	Description string
	Reusable    bool
	UsedCount   int
	Revoked     bool
	// Tags are given to nodes the key enrolls.
	Tags      []string
	CreatedAt time.Time
	ExpiresAt *time.Time
}

// Valid reports whether the key can still enroll a node at time now.
func (k AuthKey) Valid(now time.Time) bool {
	if k.Revoked {
		return false
	}
	if k.ExpiresAt != nil && !now.Before(*k.ExpiresAt) {
		return false
	}
	return k.Reusable || k.UsedCount == 0
}

// AuthKeyOptions configures a new auth key.
type AuthKeyOptions struct {
	Description string
	Reusable    bool
	// TTL is the key lifetime; zero means it never expires.
	TTL  time.Duration
	Tags []string
}

// CreateAuthKey creates a key and returns it with its one-time-visible secret.
func (s *Store) CreateAuthKey(ctx context.Context, opts AuthKeyOptions) (AuthKey, string, error) {
	return s.insertAuthKey(ctx, newSecret(AuthKeyPrefix), opts)
}

// EnsureAuthKey makes sure a key with the given secret exists, creating it
// with opts if needed. It is used to bootstrap a coordinator from config.
func (s *Store) EnsureAuthKey(ctx context.Context, secret string, opts AuthKeyOptions) (AuthKey, error) {
	if len(secret) < 16 {
		return AuthKey{}, errors.New("auth key must be at least 16 characters")
	}
	k, err := s.authKeyByHash(ctx, s.db, hashSecret(secret))
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return AuthKey{}, err
	}
	k, _, err = s.insertAuthKey(ctx, secret, opts)
	return k, err
}

func (s *Store) insertAuthKey(ctx context.Context, secret string, opts AuthKeyOptions) (AuthKey, string, error) {
	now := s.now().UTC().Truncate(time.Second)
	k := AuthKey{
		ID:          newID(),
		Description: opts.Description,
		Reusable:    opts.Reusable,
		Tags:        opts.Tags,
		CreatedAt:   now,
	}
	if opts.TTL > 0 {
		exp := now.Add(opts.TTL)
		k.ExpiresAt = &exp
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_keys (id, key_hash, description, reusable, created_at, expires_at, tags)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		k.ID, hashSecret(secret), k.Description, k.Reusable, k.CreatedAt.Unix(), unixOrNil(k.ExpiresAt), jsonList(k.Tags))
	if err != nil {
		return AuthKey{}, "", err
	}
	return k, secret, nil
}

// ListAuthKeys returns all keys, newest first.
func (s *Store) ListAuthKeys(ctx context.Context) ([]AuthKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+authKeyColumns+` FROM auth_keys ORDER BY created_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []AuthKey
	for rows.Next() {
		k, err := scanAuthKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

// RevokeAuthKey marks a key unusable. Nodes it enrolled are unaffected.
func (s *Store) RevokeAuthKey(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE auth_keys SET revoked = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

const authKeyColumns = `id, description, reusable, used_count, revoked, created_at, expires_at, tags`

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface {
	Scan(dest ...any) error
}

func (s *Store) authKeyByHash(ctx context.Context, q queryer, hash []byte) (AuthKey, error) {
	k, err := scanAuthKey(q.QueryRowContext(ctx, `SELECT `+authKeyColumns+` FROM auth_keys WHERE key_hash = ?`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return AuthKey{}, ErrNotFound
	}
	return k, err
}

func scanAuthKey(row scanner) (AuthKey, error) {
	var (
		k         AuthKey
		createdAt int64
		expiresAt sql.NullInt64
		tags      string
	)
	if err := row.Scan(&k.ID, &k.Description, &k.Reusable, &k.UsedCount, &k.Revoked, &createdAt, &expiresAt, &tags); err != nil {
		return AuthKey{}, err
	}
	if err := json.Unmarshal([]byte(tags), &k.Tags); err != nil {
		return AuthKey{}, fmt.Errorf("auth key %s tags: %w", k.ID, err)
	}
	k.CreatedAt = time.Unix(createdAt, 0).UTC()
	if expiresAt.Valid {
		t := time.Unix(expiresAt.Int64, 0).UTC()
		k.ExpiresAt = &t
	}
	return k, nil
}
