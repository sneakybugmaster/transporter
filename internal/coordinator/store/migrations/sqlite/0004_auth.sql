-- API tokens act as the admin who created them, for scripts and CI.
CREATE TABLE api_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  BLOB NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    admin_id    TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER, -- unix seconds, NULL = never
    last_used   INTEGER
);

-- Node keys expire (NULL = never); an admin can exempt a node.
ALTER TABLE nodes ADD COLUMN expires_at INTEGER;
ALTER TABLE nodes ADD COLUMN expiry_disabled INTEGER NOT NULL DEFAULT 0;

-- Admins who sign in through OIDC: "<issuer> <subject>".
ALTER TABLE admins ADD COLUMN oidc_subject TEXT;
CREATE UNIQUE INDEX admins_oidc_subject ON admins(oidc_subject);
