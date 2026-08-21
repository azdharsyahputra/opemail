# ADR 0001: Storage Consistency & Compensating Cleanup for Message Ingestion

## Status
**Accepted**

## Context
When persisting incoming email messages, the system must save two distinct artifacts:
1. **Raw Email Body (.eml stream)** into an external storage engine (`BlobStore`, e.g., local filesystem, MinIO, AWS S3).
2. **Message Metadata** (sender, subject, message ID, size, received timestamp, foreign keys) into the relational database (**PostgreSQL**).

Because PostgreSQL and the filesystem (or cloud object storage) reside across separate transaction boundaries, they cannot participate in a single unified atomic transaction without distributed two-phase commit (2PC) coordinators.

If a naive transactional approach is assumed, failure modes can produce orphaned blobs or dangling database records:
- Writing blob first $\rightarrow$ DB failure/crash $\rightarrow$ **Orphan blob remains in storage**.
- Writing DB record first $\rightarrow$ Blob write failure $\rightarrow$ **Dangling metadata pointing to missing blob**.

## Decision

We adopt the **Transactional Metadata + Compensating Cleanup** pattern combined with **Asynchronous Garbage Collection**:

```text
              Store Message
                    │
                    ▼
              Put Blob
                    │
                    ▼
              blob created
                    │
                    ▼
            BEGIN DB transaction
                    │
                    ▼
             INSERT metadata
                    │
              ┌─────┴─────┐
              │           │
            success      fail
              │           │
              ▼           ▼
           COMMIT      ROLLBACK
                          │
                          ▼
                    Delete Blob (Compensating Cleanup)
```

### 1. Synchronous Compensating Cleanup
1. The raw payload is written to `BlobStore.Put(ctx, reader)`.
2. The metadata is persisted to PostgreSQL.
3. If PostgreSQL insert or commit fails, a synchronous compensating action `BlobStore.Delete(ctx, blobID)` is executed to remove the created blob.

### 2. Periodic Garbage Collection (`mailopen storage gc`)
In the event of an ungraceful crash or network interruption between the blob creation and compensating action, an asynchronous Garbage Collector scans:
- All stored blob IDs in `BlobStore.ListIDs(ctx)`
- All referenced blob IDs in PostgreSQL (`SELECT DISTINCT blob_id FROM messages`)
- Deletes unreferenced (orphaned) blobs.

## Consequences
- **Positive**: Clean decoupling between relational metadata and high-volume payload storage.
- **Positive**: Resilient against partial storage failure without locking the database.
- **Positive**: Works seamlessly with any pluggable `BlobStore` backend (Local Filesystem, S3, MinIO, GCS).
