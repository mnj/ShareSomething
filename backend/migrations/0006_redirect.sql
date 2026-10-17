-- Link shares can redirect automatically after showing the target for `redirect_secs` seconds.
ALTER TABLE shares ADD COLUMN redirect_secs INTEGER;
