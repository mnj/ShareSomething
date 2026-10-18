-- Share modes: time-lock, owner approval, open notifications, split (k-of-n) keys.
ALTER TABLE shares ADD COLUMN available_from INTEGER;
ALTER TABLE shares ADD COLUMN require_approval INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shares ADD COLUMN notify_on_open INTEGER NOT NULL DEFAULT 0;
ALTER TABLE shares ADD COLUMN split_k INTEGER;
ALTER TABLE shares ADD COLUMN split_n INTEGER;

-- Where a user wants notifications besides the in-app list (Slack/Teams/Mattermost-style webhook).
ALTER TABLE users ADD COLUMN notify_webhook TEXT;

-- An open waiting for the owner's decision. The requester proves it's them with `secret`.
CREATE TABLE approvals (
    id               TEXT    PRIMARY KEY,
    share_id         TEXT    NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    secret_hash      BLOB    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'pending',  -- pending | approved | denied | used
    requester_label  TEXT,
    ip               TEXT    NOT NULL,
    country          TEXT,
    user_agent       TEXT,
    created_at       INTEGER NOT NULL,
    decided_at       INTEGER,
    decided_by       INTEGER,
    expires_at       INTEGER NOT NULL
);
CREATE INDEX approvals_share ON approvals(share_id, status);

-- In-app notifications for users.
CREATE TABLE notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    kind        TEXT    NOT NULL,      -- share_opened | approval_requested | ...
    share_id    TEXT,
    approval_id TEXT,
    message     TEXT    NOT NULL,
    read_at     INTEGER
);
CREATE INDEX notifications_user ON notifications(user_id, id);
