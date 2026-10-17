CREATE TABLE owner (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash     TEXT    NOT NULL,
    totp_secret       TEXT,
    totp_last_step    INTEGER,
    created_at        INTEGER NOT NULL
);

CREATE TABLE owner_sessions (
    token_hash  BLOB    PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    mfa_at      INTEGER
);

CREATE TABLE shares (
    id                  TEXT    PRIMARY KEY,
    slug                TEXT    NOT NULL UNIQUE,
    slug_generator      TEXT    NOT NULL,
    slug_opts           TEXT    NOT NULL DEFAULT '{}',
    kind                TEXT    NOT NULL,          -- text | link | credential | files
    title               TEXT,
    enc_mode            TEXT    NOT NULL,          -- e2e | server
    enc_meta            TEXT    NOT NULL DEFAULT '{}',
    ciphertext          BLOB,                      -- NULL once burned / expired / revoked
    passphrase_required INTEGER NOT NULL DEFAULT 0,
    passphrase_verifier BLOB,                      -- e2e only: sha256(client verifier)
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    require_owner_mfa   INTEGER NOT NULL DEFAULT 0,
    max_views           INTEGER,
    views               INTEGER NOT NULL DEFAULT 0,
    expires_at          INTEGER,
    created_at          INTEGER NOT NULL,
    revoked_at          INTEGER,
    burned_at           INTEGER
);

CREATE TABLE policy_rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id     TEXT    NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    grp          TEXT    NOT NULL,                 -- include | require | exclude
    rule_type    TEXT    NOT NULL,
    value        TEXT    NOT NULL DEFAULT '{}',
    auth_method  TEXT
);
CREATE INDEX policy_rules_share ON policy_rules(share_id);

CREATE TABLE access_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id    TEXT    NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    ip          TEXT    NOT NULL,
    country     TEXT,
    identity    TEXT,
    user_agent  TEXT,
    outcome     TEXT    NOT NULL
);
CREATE INDEX access_log_share ON access_log(share_id, ts);
