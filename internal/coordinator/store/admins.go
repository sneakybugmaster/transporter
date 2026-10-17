package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

// SessionTokenPrefix starts every admin session token.
const SessionTokenPrefix = "trs_"

var (
	// ErrConflict is returned when a unique value (name, username) is taken.
	ErrConflict = errors.New("already exists")
	// ErrInvalidCredentials is returned for a wrong username or password.
	ErrInvalidCredentials = errors.New("invalid username or password")
	// ErrSetupDone is returned when creating the first admin after setup.
	ErrSetupDone = errors.New("setup has already been completed")
)

// Admin is a user of the configuration UI.
type Admin struct {
	ID        string
	Username  string
	CreatedAt time.Time
	// HasPassword is false for admins who sign in through OIDC only.
	HasPassword bool
}

// ValidationError reports input that breaks a rule (as opposed to a failure).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// ValidateCredentials checks username and password requirements.
func ValidateCredentials(username, password string) error {
	if l := utf8.RuneCountInString(strings.TrimSpace(username)); l < 1 || l > 64 {
		return &ValidationError{"username must be 1-64 characters"}
	}
	if l := utf8.RuneCountInString(password); l < 10 || l > 256 {
		return &ValidationError{"password must be 10-256 characters"}
	}
	return nil
}

// AdminCount returns the number of admins.
func (s *Store) AdminCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n)
	return n, err
}

// CreateFirstAdmin creates the initial admin. It fails with ErrSetupDone if
// any admin exists, atomically, so two concurrent setups cannot both win.
func (s *Store) CreateFirstAdmin(ctx context.Context, username, password string) (Admin, error) {
	var a Admin
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrSetupDone
		}
		var err error
		a, err = insertAdmin(ctx, tx, s.now(), username, password)
		return err
	})
	return a, err
}

// CreateAdmin adds another admin.
func (s *Store) CreateAdmin(ctx context.Context, username, password string) (Admin, error) {
	var a Admin
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var err error
		a, err = insertAdmin(ctx, tx, s.now(), username, password)
		return err
	})
	return a, err
}

func insertAdmin(ctx context.Context, tx *sql.Tx, now time.Time, username, password string) (Admin, error) {
	if err := ValidateCredentials(username, password); err != nil {
		return Admin{}, err
	}
	a := Admin{ID: newID(), Username: strings.TrimSpace(username), CreatedAt: now.UTC().Truncate(time.Second), HasPassword: true}
	_, err := tx.ExecContext(ctx, `INSERT INTO admins (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		a.ID, a.Username, hashPassword(password), a.CreatedAt.Unix())
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return Admin{}, ErrConflict
	}
	return a, err
}

// Authenticate checks a username and password.
func (s *Store) Authenticate(ctx context.Context, username, password string) (Admin, error) {
	var (
		a    Admin
		hash string
		at   int64
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, created_at FROM admins WHERE username = ?`,
		strings.TrimSpace(username)).Scan(&a.ID, &a.Username, &hash, &at)
	if errors.Is(err, sql.ErrNoRows) {
		_, _ = verifyPassword(password, dummyHash()) // equalise timing
		return Admin{}, ErrInvalidCredentials
	}
	if err != nil {
		return Admin{}, err
	}
	if hash == "" { // signs in through OIDC only
		_, _ = verifyPassword(password, dummyHash())
		return Admin{}, ErrInvalidCredentials
	}
	ok, err := verifyPassword(password, hash)
	if err != nil {
		return Admin{}, err
	}
	if !ok {
		return Admin{}, ErrInvalidCredentials
	}
	a.CreatedAt = time.Unix(at, 0).UTC()
	a.HasPassword = true
	return a, nil
}

// ChangePassword replaces an admin's password after checking the current
// one, and ends all of that admin's other sessions.
func (s *Store) ChangePassword(ctx context.Context, adminID, current, next, keepSessionToken string) error {
	var username, hash string
	err := s.db.QueryRowContext(ctx, `SELECT username, password_hash FROM admins WHERE id = ?`, adminID).Scan(&username, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if ok, err := verifyPassword(current, hash); err != nil || !ok {
		return ErrInvalidCredentials
	}
	if err := ValidateCredentials(username, next); err != nil {
		return err
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE admins SET password_hash = ? WHERE id = ?`, hashPassword(next), adminID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE admin_id = ? AND token_hash != ?`, adminID, hashSecret(keepSessionToken))
		return err
	})
}

// CreateSession starts a session for an admin and returns its token.
func (s *Store) CreateSession(ctx context.Context, adminID string, ttl time.Duration) (string, time.Time, error) {
	now := s.now().UTC()
	token := newSecret(SessionTokenPrefix)
	expires := now.Add(ttl).Truncate(time.Second)
	// Opportunistically clean up expired sessions.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		return "", time.Time{}, err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, admin_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		hashSecret(token), adminID, now.Unix(), expires.Unix())
	return token, expires, err
}

// SessionAdmin returns the admin owning a valid session token.
func (s *Store) SessionAdmin(ctx context.Context, token string) (Admin, error) {
	var (
		a  Admin
		at int64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT a.id, a.username, a.created_at, a.password_hash != '' FROM sessions s JOIN admins a ON a.id = s.admin_id
		 WHERE s.token_hash = ? AND s.expires_at > ?`, hashSecret(token), s.now().Unix()).Scan(&a.ID, &a.Username, &at, &a.HasPassword)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, ErrNotFound
	}
	a.CreatedAt = time.Unix(at, 0).UTC()
	return a, err
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hashSecret(token))
	return err
}

// OIDCAdmin returns the admin linked to an OIDC subject ("<issuer> <sub>"),
// creating one named username on first sign-in. Such admins have no
// password. An existing password admin with the same name is never linked:
// that could hand their account to whoever controls the identity provider
// account, so it is reported as ErrConflict instead.
func (s *Store) OIDCAdmin(ctx context.Context, subject, username string) (Admin, error) {
	var a Admin
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var at int64
		err := tx.QueryRowContext(ctx, `SELECT id, username, created_at FROM admins WHERE oidc_subject = ?`, subject).
			Scan(&a.ID, &a.Username, &at)
		if err == nil {
			a.CreatedAt = time.Unix(at, 0).UTC()
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if l := utf8.RuneCountInString(username); l < 1 || l > 64 {
			return &ValidationError{"username from the identity provider must be 1-64 characters"}
		}
		now := s.now().UTC().Truncate(time.Second)
		a = Admin{ID: newID(), Username: username, CreatedAt: now}
		_, err = tx.ExecContext(ctx, `INSERT INTO admins (id, username, password_hash, created_at, oidc_subject) VALUES (?, ?, '', ?, ?)`,
			a.ID, a.Username, now.Unix(), subject)
		if err != nil && strings.Contains(err.Error(), "UNIQUE") {
			return ErrConflict
		}
		return err
	})
	return a, err
}
