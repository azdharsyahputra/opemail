DROP INDEX IF EXISTS idx_mailboxes_identity_provider;
ALTER TABLE mailboxes DROP COLUMN IF EXISTS identity_provider;
