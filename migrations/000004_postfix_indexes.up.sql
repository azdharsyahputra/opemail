CREATE UNIQUE INDEX IF NOT EXISTS idx_mailboxes_email_lower
ON mailboxes (LOWER(email));

CREATE UNIQUE INDEX IF NOT EXISTS idx_domains_name_lower
ON domains (LOWER(name));

CREATE INDEX IF NOT EXISTS idx_aliases_source_lower
ON aliases (LOWER(source));
