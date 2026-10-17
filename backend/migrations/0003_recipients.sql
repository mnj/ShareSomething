-- Recipient sign-in: one session cookie can carry several verified identities.
CREATE TABLE recipient_sessions (
    token_hash  BLOB    PRIMARY KEY,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE recipient_identities (
    session_hash BLOB    NOT NULL REFERENCES recipient_sessions(token_hash) ON DELETE CASCADE,
    email        TEXT    NOT NULL,
    method       TEXT    NOT NULL,       -- email_otp | oidc:<provider>
    verified_at  INTEGER NOT NULL,
    PRIMARY KEY (session_hash, email, method)
);

CREATE TABLE email_challenges (
    id          TEXT    PRIMARY KEY,
    email       TEXT    NOT NULL,
    code_hash   BLOB    NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE oidc_states (
    state_hash     BLOB    PRIMARY KEY,
    provider       TEXT    NOT NULL,
    pkce_verifier  TEXT    NOT NULL,
    nonce          TEXT    NOT NULL,
    next           TEXT    NOT NULL,
    expires_at     INTEGER NOT NULL
);
