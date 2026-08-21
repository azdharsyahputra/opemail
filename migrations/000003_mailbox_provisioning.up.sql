ALTER TABLE mailboxes
ADD COLUMN IF NOT EXISTS provisioning_status TEXT NOT NULL DEFAULT 'pending';
