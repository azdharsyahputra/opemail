CREATE TABLE IF NOT EXISTS smtp_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    username VARCHAR(128) NOT NULL UNIQUE,
    secret_hash TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT smtp_credentials_status_check CHECK (status IN ('active', 'revoked'))
);

CREATE INDEX IF NOT EXISTS idx_smtp_credentials_domain_id ON smtp_credentials(domain_id);
CREATE INDEX IF NOT EXISTS idx_smtp_credentials_username ON smtp_credentials(LOWER(username));
CREATE UNIQUE INDEX IF NOT EXISTS smtp_credentials_domain_name_active_unique
    ON smtp_credentials(domain_id, LOWER(name)) WHERE status = 'active';

-- Postfix only needs the login name for sender authorization. Dovecot needs
-- the Argon2id secret hash for SMTP AUTH authentication.
GRANT SELECT (id, domain_id, name, username, status, created_at, last_used_at, revoked_at)
    ON smtp_credentials TO mailopen_postfix;
GRANT SELECT (id, domain_id, username, secret_hash, status)
    ON smtp_credentials TO mailopen_dovecot;
