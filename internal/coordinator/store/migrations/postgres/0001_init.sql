-- Postgres version of sqlite/0001_init.sql. Keep the files in step: the
-- same number is the same schema version in both dialects.
CREATE TABLE auth_keys (
    id          TEXT PRIMARY KEY,
    key_hash    BYTEA NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    reusable    BOOLEAN NOT NULL DEFAULT FALSE,
    used_count  INTEGER NOT NULL DEFAULT 0,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT
);

CREATE TABLE nodes (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    hostname      TEXT NOT NULL,
    os            TEXT NOT NULL DEFAULT '',
    wg_public_key BYTEA NOT NULL UNIQUE,
    ipv4          TEXT NOT NULL UNIQUE,
    token_hash    BYTEA NOT NULL UNIQUE,
    endpoints     TEXT NOT NULL DEFAULT '[]',
    auth_key_id   TEXT REFERENCES auth_keys(id) ON DELETE SET NULL,
    created_at    BIGINT NOT NULL,
    last_seen     BIGINT NOT NULL
);
