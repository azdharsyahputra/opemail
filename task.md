# W2.10 — Production Hardening, Observability & Mail Queue

## 0. Target Architecture & Scope

```text
                                MailOpen Control Plane
                                          │
        ┌───────────────────┬─────────────┴─────────────┬───────────────────┐
        │                   │                           │                   │
  CONTROL PLANE        MAIL ENGINES                 SECURITY          OBSERVABILITY & QUEUE
        │                   │                           │                   │
   PostgreSQL            Postfix                     TLS Certs          Structured slog
   Domains & Mailboxes   Dovecot IMAP/IMAPS          DKIM Keystore      Prometheus /metrics
   Aliases               Maildir++ Storage           SPF & DMARC        Health Live/Ready/Deep
   Mailbox Quotas        Postfix Queue Controller    Rspamd & ClamAV    Message Events & Trace
   Audit Trail Log       (postqueue/postcat/super)   Anti-Abuse Limits  Audit Trail Logs
                                                                        Backup & Disaster Recovery
```

---

## 1. Definition of Done Checklist

- [ ] **W2.10.1 Database Migrations for Message Events & Audit Trail**
  - [ ] Migration `000009_message_events_and_audit.up.sql` (`message_events`, `audit_logs`)
  - [ ] Migration `000009_message_events_and_audit.down.sql`
  - [ ] Package `internal/audit/` (models, repository, postgres implementation, service, event tracer)
- [ ] **W2.10.2 Mail Queue Management (`internal/queue/`)**
  - [ ] Postfix queue driver (`postqueue -p`, `postcat`, `postsuper -d/-h/-r`, `postqueue -f`)
  - [ ] Robust queue parser for Active, Deferred, Hold, Corrupt, Incoming queues
  - [ ] Queue inspection, deletion, hold, retry, and flush controls
  - [ ] CLI: `mailopen queue status / list / inspect / retry / delete / flush`
- [ ] **W2.10.3 Bounce Processing & Enhanced Status Code Classification (`internal/bounce/`)**
  - [ ] Enhanced status code parser (`5.1.1`, `4.7.1`, `5.7.1`, `5.2.2`, etc.)
  - [ ] Category classifier (RecipientUnknown, MailboxFull, DomainUnknown, PolicyRejection, SpamRejection, TLSFailure, etc.)
  - [ ] DSN multipart/report parser & unit tests
- [ ] **W2.10.4 Storage Quota Engine & Reconciliation (`internal/quota/`)**
  - [ ] Fast path quota lookup & counter validation
  - [ ] Background Maildir++ disk usage calculator & DB reconciler
  - [ ] Thresholds (<80% OK, 80-90% Warning, 90-99% Critical, >=100% Full)
  - [ ] CLI: `mailopen quota show <email>`, `mailopen quota reconcile <email>`
- [ ] **W2.10.5 Structured Logging (`log/slog`) & Secret Masking (`internal/logger/`)**
  - [ ] JSON slog logger with zero-secret filter (masks passwords, AUTH PLAIN hashes, DKIM private keys, email bodies)
- [ ] **W2.10.6 Metrics & Health Endpoints (`internal/metrics/`, `internal/health/`)**
  - [ ] Prometheus metrics registry (`/metrics`)
  - [ ] Health endpoints: `/health/live`, `/health/ready`, `/health/deep`
  - [ ] CLI: `mailopen health [live|ready|deep]`
- [ ] **W2.10.7 Disaster Recovery, Backup & Restore (`internal/backup/`)**
  - [ ] Complete bundle: PostgreSQL dump + Maildir + DKIM private keys + TLS private keys + Configs + `backup.json` manifest
  - [ ] AES-256-GCM encrypted backup archive
  - [ ] Backup verification with SHA-256 checksums
  - [ ] Disposable environment restore testing
  - [ ] CLI: `mailopen backup create / verify / restore`
- [ ] **W2.10.8 Configuration Validator & Full System Doctor**
  - [ ] `mailopen config validate` across all 8 subsystems
  - [ ] `mailopen system doctor` (10-category comprehensive diagnostic report)
  - [ ] `mailopen message trace <message-id>`
- [ ] **W2.10.9 Full Regression & Integration Tests**
  - [ ] Queue parser and management tests
  - [ ] Bounce classification tests
  - [ ] Quota calculation & reconciliation tests
  - [ ] Audit log & event tracing tests
  - [ ] Backup creation, encryption, verification, and restore tests
  - [ ] Full regression across W2.1 - W2.10 (`go test -count=1 -v ./...` 100% PASS)
