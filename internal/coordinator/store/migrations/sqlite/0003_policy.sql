-- Tags place nodes in access-control policy; auth keys hand them out.
ALTER TABLE nodes ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';
ALTER TABLE auth_keys ADD COLUMN tags TEXT NOT NULL DEFAULT '[]';

-- Subnet routes (0.0.0.0/0 for an exit node): what the node offers, and
-- what an admin (or the policy's autoApprovers) allowed. A route is used
-- only while it is both advertised and approved.
ALTER TABLE nodes ADD COLUMN advertised_routes TEXT NOT NULL DEFAULT '[]';
ALTER TABLE nodes ADD COLUMN approved_routes TEXT NOT NULL DEFAULT '[]';

CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    time   INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
