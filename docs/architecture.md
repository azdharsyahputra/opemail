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

## Mailbox Provisioning Architecture (W2.3)

MailOpen serves as the **Control Plane** and manages mailbox provisioning and lifecycle, delegating mail access and live storage to **Dovecot**:

```text
                    MailOpen (Control Plane)
                               │
                        Mailbox Service
                               │
                       Provisioner Layer
                               │
                 ┌─────────────┴─────────────┐
                 ▼                           ▼
              Postfix                     Dovecot
                 │                           │
                 │                       Maildir++
                 │                           │
                 └─────────────┬─────────────┘
                               ▼
                        /var/vmail/...
```

### 1. Directory Structure (Dovecot Maildir++)
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
- **RFC Path Derivation**: Calculated dynamically from `domain + normalized localpart`, guarded against path traversal. Not stored in DB.

### 2. Provisioning States
Mailboxes progress through explicit provisioning states in PostgreSQL:
- `pending`: Registered in DB, awaiting filesystem/engine allocation.
- `provisioning`: Provisioner actively creating directories/configurations.
- `ready`: Maildir structure verified and ready for Dovecot.
- `failed`: Provisioning error encountered; retryable via CLI.
- `deprovisioning`: Pending filesystem cleanup.

### 3. Mailbox Doctor
Validates database record status, directory existence (`Maildir`, `cur`, `new`, `tmp`), filesystem permissions (`0750`), and process ownership (`vmail:vmail`).

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
