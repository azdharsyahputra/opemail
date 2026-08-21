# MailOpen Operations Runbook: Security & Hardening

## 1. Least-Privilege Database Isolation
Postfix and Dovecot database accounts must be granted `SELECT`-only permissions on virtual mailbox/alias tables:
```sql
GRANT SELECT ON domains, mailboxes, aliases TO mailopen_postfix;
GRANT SELECT ON domains, mailboxes TO mailopen_dovecot;
REVOKE INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM mailopen_postfix, mailopen_dovecot;
```

## 2. Filesystem Permissions & Ownership
- **Maildir Base (`/var/vmail`)**: `0750`, owned by `vmail:vmail` (UID: 5000, GID: 5000).
- **Email Blobs**: `0600`, owned by `vmail:vmail`.
- **DKIM Private Keys**: `0600`, owned by `opendkim:opendkim` in `0750` directory.
- **TLS Certificates**: `0600` on private key PEM files.

## 3. Log Redaction Policy
Log outputs must never contain:
- Plaintext user passwords or Argon2id hashes
- Base64 encoded `AUTH PLAIN` payloads
- DKIM / TLS private key material
- Encrypted backup passphrases
