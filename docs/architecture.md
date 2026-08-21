# OpenMail Architecture

## High-Level Architecture (Week 1 & 2)

```text
                           CLI (Cobra)
                                │
                                ▼
                         Application Core
                                │
          ┌─────────────────────┼─────────────────────┐
          ▼                     ▼                     ▼
    Domain Service       Mailbox Service       Message Service
          │                     │                     │
          │                     │              ┌──────┴──────┐
          │                     ▼              ▼             ▼
          │             Provisioning Layer PostgreSQL    BlobStore
          │                     │         (Metadata)     (Archive/Backup)
          │                     ▼                            │
          │            Dovecot Maildir++                     ▼
          │             (/var/vmail/...)                Filesystem /
          └─────────────────────┼────────────────────── S3 / MinIO
                                ▼
                            PostgreSQL
                         (Domains, Mailboxes)
```

## Postfix Adapter & Inbound SMTP (W2.4)

Postfix acts as the inbound SMTP Mail Transfer Agent (MTA) listening on port 25. All routing, domain, mailbox, and alias lookups are evaluated in real-time against PostgreSQL:

```text
                         INTERNET
                            │
                         TCP :25
                            │
                            ▼
                       ┌─────────┐
                       │ Postfix │
                       └────┬────┘
                            │
                    PostgreSQL lookup (Read-Only)
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
          Domains        Mailboxes       Aliases
             │              │              │
             └──────────────┴──────────────┘
                            │
                            ▼
                     /var/vmail/...
                            │
                            ▼
                     Dovecot Maildir
```

### 1. Dynamic PostgreSQL Lookups (No Reloads)
- **Virtual Domains (`pgsql-virtual-mailbox-domains.cf`)**:
  ```sql
  SELECT 1 FROM domains WHERE LOWER(name) = LOWER('%s') AND status = 'active' LIMIT 1
  ```
- **Virtual Mailboxes (`pgsql-virtual-mailbox-maps.cf`)**:
  ```sql
  SELECT 1 FROM mailboxes m
  JOIN domains d ON d.id = m.domain_id
  WHERE LOWER(m.email) = LOWER('%s')
    AND m.status = 'active'
    AND m.provisioning_status = 'ready'
  LIMIT 1
  ```
- **Virtual Aliases (`pgsql-virtual-alias-maps.cf`)**:
  ```sql
  SELECT a.destination FROM aliases a
  JOIN domains d ON d.id = a.domain_id
  WHERE LOWER(a.source) = LOWER('%s') AND d.status = 'active'
  ```

### 2. Security & Anti-Relay Baseline
- Port 25 is restricted to inbound SMTP for local virtual domains.
- Postfix uses `permit_mynetworks, reject_unauth_destination` to block open relay attempts.
- Password hashes (Argon2id) are isolated inside MailOpen/Dovecot and never exposed to Postfix.
- Database access for Postfix is strictly read-only via a dedicated user (`mailopen_postfix`).

## Mailbox Provisioning Architecture (W2.3)

MailOpen serves as the **Control Plane** and manages mailbox provisioning and lifecycle, delegating mail access and live storage to **Dovecot**:

```text
/var/vmail/
└── example.com/
    └── ajar/
        └── Maildir/
            ├── cur/
            ├── new/
            └── tmp/
```
- **Permission**: `0750`
- **Ownership**: `vmail:vmail` (UID: 5000, GID: 5000)
- **Provisioning Lifecycle**: `pending` $\rightarrow$ `provisioning` $\rightarrow$ `ready` / `failed` / `deprovisioning`.

## Storage Layer Abstraction (`internal/storage`)

Raw email payloads (RFC 5322 `.eml`) for archival, backup, export, and S3 migration are decoupled behind `BlobStore`:

```go
type BlobStore interface {
    Put(ctx context.Context, r io.Reader) (Blob, error)
    Get(ctx context.Context, id string) (io.ReadCloser, error)
    Delete(ctx context.Context, id string) error
    Exists(ctx context.Context, id string) (bool, error)
    ListIDs(ctx context.Context) ([]string, error)
}
```

## Architectural Decision Records (ADRs)

- [ADR 0001: Storage Consistency & Compensating Cleanup for Message Ingestion](adr/0001-storage-consistency-and-compensating-cleanup.md)
