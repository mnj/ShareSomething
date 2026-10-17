-- File shares: content is an encrypted manifest in shares.ciphertext plus chunked blobs on disk.
ALTER TABLE shares ADD COLUMN upload_pending INTEGER NOT NULL DEFAULT 0;
-- Server mode: DEK wrapped under the upload token while chunks are being uploaded.
ALTER TABLE shares ADD COLUMN upload_dek BLOB;
ALTER TABLE shares ADD COLUMN upload_token_hash BLOB;

CREATE TABLE share_files (
    share_id         TEXT    NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    idx              INTEGER NOT NULL,
    size             INTEGER NOT NULL,   -- plaintext bytes
    chunk_count      INTEGER NOT NULL,
    uploaded_chunks  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (share_id, idx)
);

-- Issued by a successful open; lets the recipient fetch chunks after the share burned.
CREATE TABLE download_tokens (
    token_hash   BLOB    PRIMARY KEY,
    share_id     TEXT    NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    wrapped_dek  BLOB,                   -- server mode: DEK wrapped under the token
    expires_at   INTEGER NOT NULL
);
CREATE INDEX download_tokens_share ON download_tokens(share_id);
