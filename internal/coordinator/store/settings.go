package store

import (
	"context"
	"database/sql"
	"errors"
)

// Setting keys.
const (
	SettingPublicURL = "public_url"
	// SettingPolicy holds the access-control policy (HuJSON text).
	SettingPolicy = "policy"
	// SettingDNS holds the DNS configuration (JSON).
	SettingDNS = "dns"
)

// Setting returns a setting's value, or "" if unset.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores a setting.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
