CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY,
    mailbox_id UUID NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,

    message_id TEXT,
    blob_id TEXT NOT NULL,

    sender TEXT,
    subject TEXT,
    size_bytes BIGINT NOT NULL,

    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
