-- v2 foundation: a real user model (single mode = one admin user) and the audit trail.

CREATE TABLE users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    email            TEXT UNIQUE,                     -- NULL for the single-mode owner
    name             TEXT    NOT NULL DEFAULT '',
    role             TEXT    NOT NULL DEFAULT 'member', -- admin | member | auditor
    status           TEXT    NOT NULL DEFAULT 'active', -- active | disabled
    password_hash    TEXT,
    totp_secret      TEXT,
    totp_last_step   INTEGER,
    totp_pending     TEXT,
    totp_pending_at  INTEGER,
    webauthn_user_id TEXT,
    created_at       INTEGER NOT NULL,
    last_login_at    INTEGER
);
INSERT INTO users (id, name, role, status, password_hash, totp_secret, totp_last_step, totp_pending,
                   totp_pending_at, webauthn_user_id, created_at)
SELECT id, 'Owner', 'admin', 'active', password_hash, totp_secret, totp_last_step, totp_pending,
       totp_pending_at, webauthn_user_id, created_at
FROM owner;
DROP TABLE owner;

CREATE TABLE user_sessions (
    token_hash  BLOB    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    mfa_at      INTEGER
);
INSERT INTO user_sessions (token_hash, user_id, created_at, expires_at, mfa_at)
SELECT token_hash, 1, created_at, expires_at, mfa_at FROM owner_sessions;
DROP TABLE owner_sessions;
CREATE INDEX user_sessions_user ON user_sessions(user_id);

CREATE TABLE user_passkeys (
    cred_id       TEXT    PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT    NOT NULL,
    passkey       TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);
INSERT INTO user_passkeys (cred_id, user_id, name, passkey, created_at, last_used_at)
SELECT cred_id, 1, name, passkey, created_at, last_used_at FROM owner_passkeys;
DROP TABLE owner_passkeys;

-- Every share and saved policy belongs to a user (existing ones to the single-mode owner).
ALTER TABLE shares ADD COLUMN owner_id INTEGER NOT NULL DEFAULT 1;
CREATE INDEX shares_owner ON shares(owner_id);

CREATE TABLE policy_templates_v2 (
    id          TEXT    PRIMARY KEY,
    owner_id    INTEGER NOT NULL,
    name        TEXT    NOT NULL,
    rules       TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    UNIQUE (owner_id, name)
);
INSERT INTO policy_templates_v2 (id, owner_id, name, rules, created_at)
SELECT id, 1, name, rules, created_at FROM policy_templates;
DROP TABLE policy_templates;
ALTER TABLE policy_templates_v2 RENAME TO policy_templates;

-- Append-only, hash-chained audit trail. No foreign keys: records outlive what they describe.
CREATE TABLE audit_events (
    seq           INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    actor_type    TEXT    NOT NULL,                 -- user | recipient | system
    actor_id      TEXT,
    actor_label   TEXT,
    ip            TEXT,
    user_agent    TEXT,
    action        TEXT    NOT NULL,
    target_type   TEXT,
    target_id     TEXT,
    target_label  TEXT,
    outcome       TEXT    NOT NULL,                 -- success | denied | error
    details       TEXT    NOT NULL DEFAULT '{}',
    prev_hash     BLOB    NOT NULL,
    hash          BLOB    NOT NULL
);
CREATE INDEX audit_target ON audit_events(target_type, target_id, seq);
CREATE INDEX audit_ts ON audit_events(ts);
CREATE INDEX audit_action ON audit_events(action, seq);

-- Per-shipper delivery cursor (at-least-once SIEM delivery that survives restarts).
CREATE TABLE audit_cursors (
    shipper     TEXT    PRIMARY KEY,
    last_seq    INTEGER NOT NULL,
    failures    INTEGER NOT NULL DEFAULT 0,
    last_error  TEXT,
    updated_at  INTEGER NOT NULL
);
