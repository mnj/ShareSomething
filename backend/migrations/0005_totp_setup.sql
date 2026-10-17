-- TOTP enrollment from the web UI: a new secret waits here until a code from it is confirmed.
ALTER TABLE owner ADD COLUMN totp_pending TEXT;
ALTER TABLE owner ADD COLUMN totp_pending_at INTEGER;
