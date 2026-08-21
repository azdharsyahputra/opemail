CREATE TABLE IF NOT EXISTS domain_dkim (
    id UUID PRIMARY KEY,
    domain_id UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

    selector TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'rsa-sha256',
    key_bits INTEGER NOT NULL DEFAULT 2048,

    status TEXT NOT NULL DEFAULT 'pending',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT domain_dkim_selector_unique
        UNIQUE (domain_id, selector),

    CONSTRAINT domain_dkim_status_check
        CHECK (status IN ('pending', 'active', 'revoked')),

    CONSTRAINT domain_dkim_algorithm_check
        CHECK (algorithm = 'rsa-sha256'),

    CONSTRAINT domain_dkim_key_bits_check
        CHECK (key_bits = 2048)
);

CREATE TABLE IF NOT EXISTS domain_mail_policy (
    domain_id UUID PRIMARY KEY
        REFERENCES domains(id)
        ON DELETE CASCADE,

    spf_policy TEXT NOT NULL DEFAULT 'v=spf1 mx ~all',
    dmarc_policy TEXT NOT NULL DEFAULT 'v=DMARC1; p=none',

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_domain_dkim_lookup ON domain_dkim (domain_id, status);
