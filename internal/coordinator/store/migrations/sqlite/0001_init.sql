-- Keep in step with postgres/0001_init.sql (same number, same schema).
CREATE TABLE auth_keys (
    id          TEXT PRIMARY KEY,
    key_hash    BLOB NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    reusable    INTEGER NOT NULL DEFAULT 0,
    used_count  INTEGER NOT NULL DEFAULT 0,
    revoked     INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER          -- unix seconds, NULL = never
);

CREATE TABLE nodes (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    hostname      TEXT NOT NULL,
    os            TEXT NOT NULL DEFAULT '',
    wg_public_key BLOB NOT NULL UNIQUE,
    ipv4          TEXT NOT NULL UNIQUE,
    token_hash    BLOB NOT NULL UNIQUE,
    endpoints     TEXT NOT NULL DEFAULT '[]', -- JSON array of "ip:port"
    auth_key_id   TEXT REFERENCES auth_keys(id) ON DELETE SET NULL,
    created_at    INTEGER NOT NULL,
    last_seen     INTEGER NOT NULL
);
