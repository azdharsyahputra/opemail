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
          │                     │              ▼             ▼
          │                     │          PostgreSQL    BlobStore
          │                     │         (Metadata)     (Raw .eml)
          └─────────────────────┼─────────────────────┘      │
                                ▼                            ▼
                            PostgreSQL                  Filesystem /
                         (Domains, Mailboxes)           S3 / MinIO
```

## Storage Layer Abstraction (`internal/storage`)

Raw email payloads (RFC 5322 `.eml`) are decoupled from database metadata and isolated behind the `BlobStore` interface:

```go
type BlobStore interface {
    Put(ctx context.Context, r io.Reader) (Blob, error)
    Get(ctx context.Context, id string) (io.ReadCloser, error)
    Delete(ctx context.Context, id string) error
    Exists(ctx context.Context, id string) (bool, error)
}
```

### Prefix Sharding
Under `FilesystemBlobStore`, blobs are sharded by their content SHA-256 hash prefix:
```text
/var/lib/openmail/blobs/
├── c5/
│   └── c54b79cdf07d6edb853acef044a6349b293632415ddc15cf9509bfc81beb04bd
├── 7f/
│   └── 7f9a...
└── tmp/
```
- **Email/User Immutability**: Blobs are keyed by content hash, not email address. Changing a user's email address does not require reorganizing storage.
- **Deduplication**: Identical payloads share storage space.
- **Control Plane Separation**: OpenMail functions as the control plane for configuration and provisioning, integrating cleanly with downstream mail storage (e.g. Dovecot/Postfix).
