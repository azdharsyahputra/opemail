CREATE TABLE IF NOT EXISTS system_settings (
    key VARCHAR(64) PRIMARY KEY,
    value TEXT NOT NULL,
    category VARCHAR(32) NOT NULL DEFAULT 'general',
    description VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

INSERT INTO system_settings (key, value, category, description) VALUES
    ('default_mailbox_quota_mb', '1024', 'mailbox', 'Default quota in MB for newly created mailboxes'),
    ('max_message_size_mb', '50', 'transport', 'Maximum allowed email message size in MB'),
    ('max_recipients_per_email', '50', 'transport', 'Maximum recipients allowed in a single outgoing email'),
    ('server_hostname', 'mail.domain.com', 'network', 'Primary mail server fully qualified domain name'),
    ('public_ip_override', '', 'network', 'Manual static IP override (leave blank for auto-detect)'),
    ('tls_enforce_level', 'opportunistic', 'security', 'TLS enforcement level: opportunistic or strict'),
    ('dkim_default_bits', '2048', 'security', 'Default RSA key bit size for DKIM key generation: 2048 or 4096'),
    ('spam_reject_score', '15.0', 'security', 'Spam score threshold for immediate message rejection'),
    ('spam_greylist_score', '6.0', 'security', 'Spam score threshold for greylisting delay'),
    ('audit_retention_days', '90', 'observability', 'Retention period in days for audit trail logs'),
    ('prometheus_enabled', 'true', 'observability', 'Enable Prometheus /metrics exporter endpoint')
ON CONFLICT (key) DO NOTHING;
