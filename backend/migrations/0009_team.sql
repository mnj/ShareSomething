-- Team mode: invites, SSO-provisioned members, groups and org-wide policies.
ALTER TABLE users ADD COLUMN invite_token_hash BLOB;
ALTER TABLE users ADD COLUMN invite_expires_at INTEGER;
ALTER TABLE users ADD COLUMN invited_by INTEGER;
-- Set when the account was created by (and signs in with) an SSO provider.
ALTER TABLE users ADD COLUMN sso_provider TEXT;

CREATE TABLE groups (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT    NOT NULL UNIQUE,
    description  TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL
);

CREATE TABLE group_members (
    group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX group_members_user ON group_members(user_id);

-- Org policies set by admins (JSON, see org::settings::OrgSettings).
CREATE TABLE org_settings (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    settings    TEXT    NOT NULL DEFAULT '{}',
    updated_at  INTEGER,
    updated_by  INTEGER
);
INSERT INTO org_settings (id, settings) VALUES (1, '{}');

-- OIDC round trips are now either recipient verification or member sign-in.
ALTER TABLE oidc_states ADD COLUMN purpose TEXT NOT NULL DEFAULT 'recipient';
