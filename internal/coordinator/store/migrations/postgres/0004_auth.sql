CREATE TABLE api_tokens (
    id          TEXT PRIMARY KEY,
    token_hash  BYTEA NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    admin_id    TEXT NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    created_at  BIGINT NOT NULL,
    expires_at  BIGINT,
    last_used   BIGINT
);

ALTER TABLE nodes ADD COLUMN expires_at BIGINT;
ALTER TABLE nodes ADD COLUMN expiry_disabled BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE admins ADD COLUMN oidc_subject TEXT;
CREATE UNIQUE INDEX admins_oidc_subject ON admins(oidc_subject);
