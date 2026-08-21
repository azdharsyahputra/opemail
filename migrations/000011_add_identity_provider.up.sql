ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS identity_provider VARCHAR(32) NOT NULL DEFAULT 'local';
ALTER TABLE mailboxes ALTER COLUMN password_hash DROP NOT NULL;
CREATE INDEX IF NOT EXISTS idx_mailboxes_identity_provider ON mailboxes (identity_provider);
