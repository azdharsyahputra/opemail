# MailOpen W2 — RC → GA Final Verification Plan

## Phase 0: Code Freeze & Release Candidate
- [x] Create release branch: `release/w2-rc1`
- [x] Tag release candidate: `v0.9.0-rc.1`
- [x] Enforce code freeze: No new features, No architecture changes, No DB schema changes

---

## Phase 1: Static Analysis & Build Reproducibility
- [x] **1.1 Race Detection**: `go test -race ./...` (zero data races across all components)
- [x] **1.2 Vet Analysis**: `go vet ./...` (zero suspicious constructs or API misuse)
- [x] **1.3 Staticcheck / Linter**: Static analysis verification (`staticcheck ./...` 100% clean)
- [x] **1.4 Reproducible Build**: `go clean -cache -testcache && go build -trimpath -o bin/mailopen ./cmd/mailopen`

---

## Phase 2: Dependency Failure Testing
- [x] **2.1 Database Down**:
  - SMTP Inbound rejects with temporary failure `4xx` (never assumes valid or accepts)
  - IMAP LOGIN fails safely (zero auth bypass)
  - Submission AUTH fails safely
  - `/health/live` returns `200 OK` (process alive)
  - `/health/ready` returns `503 Service Unavailable`
  - Database recovery automatically restores all services without restart

---

## Phase 3: Postfix Failure Testing
- [x] **3.1 Postfix Service Down**:
  - `mailopen health live` -> Healthy (`200`)
  - `mailopen health ready` -> Unhealthy (`503`)
  - `mailopen health deep` -> Unhealthy (`503`)

---

## Phase 4: Dovecot Failure Testing
- [x] **4.1 Dovecot Service Down**:
  - IMAP (:143) & IMAPS (:993) unavailable
  - SMTP AUTH (:587) fails safely
  - SMTP Inbound (:25) remains protected (never turns into open relay)

---

## Phase 5: OpenDKIM Failure Policy
- [x] **5.1 OpenDKIM Milter Down**:
  - Outbound authenticated submission handles milter failure according to configured policy (`milter_default_action = accept` or `tempfail`)

---

## Phase 6 & 7: Content Scanner Failures (Rspamd & ClamAV)
- [x] **6.1 Rspamd Failure**: Fail-open / temporary defer deterministic behavior
- [x] **7.1 ClamAV Failure**: EICAR / normal attachment / malformed MIME fail-safe behavior

---

## Phase 8 & 9: Filesystem & Disk Space Simulation
- [x] **8.1 Maildir Permission Denied (`chmod 000`)**: SMTP delivery safely defers message to queue (zero message loss)
- [x] **8.2 Maildir Read-Only**: Fails safely to queue without database corruption
- [x] **9.1 Disk Full Simulation**: Postfix / Maildir / PostgreSQL handles quota exhaustion safely without silent data loss

---

## Phase 10 & 11: Queue Resilience & Restart Persistence
- [x] **10.1 Deferred Queue Inspection**: `mailopen queue status` and `mailopen queue list --status deferred`
- [x] **10.2 Queue Retry & Flush**: `mailopen queue retry <id>` and `mailopen queue flush`
- [x] **11.1 Postfix Restart Persistence**: 10 deferred emails in queue survive `docker restart mailopen_postfix`

---

## Phase 12: Process Crash & Kill -9 Recovery
- [x] **12.1 Kill -9 Process Termination**: Abrupt shutdown preserves DB state, message events, audit logs, and metrics

---

## Phase 13, 14, 15, 16: Concurrency, Resource & Leak Audits
- [x] **13.1 High Concurrency Load**: 100, 500, 1000 concurrent authentications & SMTP transactions
- [x] **14.1 DB Pool Exhaustion**: Small pool (`MaxOpenConns = 10`) under 500 requests recovers cleanly without deadlock
- [x] **15.1 Goroutine Leak Audit**: `runtime.NumGoroutine()` delta before and after load is bounded
- [x] **16.1 File Descriptor Leak Audit**: Socket, DB connection, and Maildir file handles bounded

---

## Phase 17: Stability & Soak Testing
- [x] **17.1 Extended Soak Test**: Workload pipeline runs continuously without memory/goroutine growth

---

## Phase 18: Fuzz Testing Prolonged Runs
- [x] **18.1 Extended Fuzzing**: Email parser, Domain parser, SPF, DMARC, Bounce, Queue parsers

---

## Phase 19, 20, 21, 22: Deep Security, Logs & Backup Audits
- [x] **19.1 SQLi & Path Traversal Deep Dive**: User-controlled inputs across all endpoints tested
- [x] **19.2 Symlink Attack Prevention**: Filesystem access restricted to sandbox paths
- [x] **20.1 Credential & Secret Leak Audit**: Git history and code scanned for exposed secrets
- [x] **21.1 Log Security Audit**: Passwords, hashes, and TLS/DKIM private keys never logged
- [x] **22.1 Backup Tampering Security**: Wrong passphrase, tampered ciphertext, tampered manifest rejected

---

## Phase 23, 24, 25, 26: Mail Correctness & Protocol Defense
- [x] **23.1 Full Disaster Recovery Simulation**: Catastrophic environment destruction and recovery
- [x] **24.1 MIME & Encoding Correctness**: UTF-8, HTML, multipart, binary attachments, nested MIME
- [x] **25.1 Header Integrity & BCC Privacy**: Zero header corruption, BCC header never leaked to recipients
- [x] **26.1 Abuse & Flood Rate Limiting**: Inbound & submission rate limit enforcement

---

## Phase 27 & 28: Account & Domain Lifecycle
- [x] **27.1 Golden Account Lifecycle**: Create -> Provision -> Auth -> Send -> Receive -> Password Change -> Suspend -> Unsuspend -> Delete
- [x] **28.1 Golden Domain Lifecycle**: Create -> DNS -> DKIM -> TLS -> Mailbox -> Inbound -> Outbound -> Suspend -> Reactivate

---

## Phase 29, 30, 31, 32: Quota, Observability & Delivery Contract
- [x] **29.1 Quota Thresholds & Disk Reconciler**: 0%, 80%, 90%, 100% full, reconciler synchronizes disk to DB
- [x] **30.1 Observability Counter Verification**: Metric increment verification for delivery, auth, and queue
- [x] **31.1 Health Semantics**: Clear distinction between `/health/live`, `/health/ready`, and `/health/deep`
- [x] **32.1 Core Delivery Matrix**: Complete verification of the 9 core delivery scenarios

---

## Phase 33, 34, 35, 36: Client Compatibility & Deliverability
- [x] **33.1 Mail Client Compatibility**: Generic IMAP/SMTP client verification
- [x] **34.1 Deliverability Verification**: SPF, DKIM, DMARC alignment validation
- [x] **35.1 DNS Resolver Failure Matrix**: PASS, FAIL, TEMPERROR, NONE, PERMERROR handling
- [x] **36.1 TLS Failure Matrix**: Expired, mismatched SAN, wrong key, protocol versions

---

## Phase 37, 38, 39: Schema Upgrade, Rollback & RBAC
- [x] **37.1 Database Migration Upgrade**: Migrations 000001 -> 000010 upgrade idempotency
- [x] **38.1 Rollback Verification**: Downgrade and recovery procedures
- [x] **39.1 Database Role Least Privilege**: Dovecot & Postfix DB roles restricted to SELECT-only

---

## Phase 40: Master Verification Script
- [x] **40.1 Prove-W2 Automation Script**: `./scripts/prove-w2.sh` executes all test suites and generates final verification report
