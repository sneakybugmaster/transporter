CREATE TABLE admins (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    BIGINT NOT NULL
);
-- Usernames are case-insensitive (SQLite: COLLATE NOCASE).
CREATE UNIQUE INDEX admins_username ON admins (lower(username));

CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    admin_id   TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
