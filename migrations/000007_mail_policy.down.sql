ALTER TABLE domain_mail_policy
    DROP COLUMN IF EXISTS spam_threshold,
    DROP COLUMN IF EXISTS reject_threshold,
    DROP COLUMN IF EXISTS quarantine_enabled,
    DROP COLUMN IF EXISTS max_message_size,
    DROP COLUMN IF EXISTS rbl_policy,
    DROP COLUMN IF EXISTS rdns_policy;
