-- Owner passkeys (WebAuthn). `passkey` is webauthn-rs' serialised Passkey.
ALTER TABLE owner ADD COLUMN webauthn_user_id TEXT;

CREATE TABLE owner_passkeys (
    cred_id       TEXT    PRIMARY KEY,    -- base64url credential id
    name          TEXT    NOT NULL,
    passkey       TEXT    NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);

-- Named, reusable access policies.
CREATE TABLE policy_templates (
    id          TEXT    PRIMARY KEY,
    name        TEXT    NOT NULL UNIQUE,
    rules       TEXT    NOT NULL,         -- JSON array of PolicyRule
    created_at  INTEGER NOT NULL
);
