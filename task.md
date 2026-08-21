# MailOpen W2 — Core Proof Test Plan

## 0. Testing Philosophy & Levels

```text
L1 — Unit
     business logic / parser / validator / dkim / spf / dmarc / bounce / quota
L2 — Integration
     PostgreSQL / filesystem / Postfix / Dovecot / Rspamd / ClamAV
L3 — Protocol
     SMTP / IMAP / STARTTLS / SASL / Protocol Compliance
L4 — Failure & Recovery
     crash / corrupt data / unavailable dependency / retry / disaster recovery
L5 — Security & Abuse
     auth bypass / injection / enumeration / privilege / resource abuse / timing
```

---

## 1. Definition of Done Checklist (±300 Testcases)

### 1.1 Domain Management (DOMAIN-001 to DOMAIN-008)
- [x] **DOMAIN-001**: Create valid domain (`example.com` -> 201/active)
- [x] **DOMAIN-002**: Duplicate domain rejected, DB contains exactly 1
- [x] **DOMAIN-003**: Case normalization (`Example.COM` -> `example.com`)
- [x] **DOMAIN-004**: Invalid domains (`foo`, `foo_`, `foo..com`, `.foo.com`, `foo.com.`) rejected without DB mutation
- [x] **DOMAIN-005**: Domain deletion cascade behavior (mailbox, alias, DKIM, policy)
- [x] **DOMAIN-006**: Domain with active mailbox protected from accidental deletion
- [x] **DOMAIN-007**: Suspended domain causes SMTP inbound, IMAP auth, and Submission rejection
- [x] **DOMAIN-008**: Reactivation (`active` -> `suspended` -> `active`) restores all services without restart

### 1.2 Mailbox Lifecycle (MAILBOX-001 to MAILBOX-010)
- [x] **MAILBOX-001**: Create mailbox
- [x] **MAILBOX-002**: Duplicate mailbox rejected
- [x] **MAILBOX-003**: Case insensitive mailbox (`Ajar@example.com` == `ajar@EXAMPLE.COM`)
- [x] **MAILBOX-004**: Invalid localpart (`foo/`, `foo..`, `../foo`, `foo\bar`) rejected
- [x] **MAILBOX-005**: Password hashing verified (Argon2id, plaintext not stored)
- [x] **MAILBOX-006**: Dynamic password change without restarting Postfix/Dovecot/MailOpen
- [x] **MAILBOX-007**: Suspend mailbox rejects SMTP inbound, IMAP, and SMTP AUTH
- [x] **MAILBOX-008**: Resume mailbox re-enables all services
- [x] **MAILBOX-009**: Delete mailbox cleans DB, Maildir, and cascades properly
- [x] **MAILBOX-010**: Provisioning crash recovery (interrupted `provisioning` recovered to `ready`)

### 1.3 Maildir / Filesystem (FS-001 to FS-012)
- [x] **FS-001**: Standard Maildir structure (`cur/`, `new/`, `tmp/`)
- [x] **FS-002**: Directory permissions `0750` with `vmail:vmail`
- [x] **FS-003**: File permissions `0600`
- [x] **FS-004**: Path traversal rejection (`../../etc`, `foo/../../`, `..\..\etc`)
- [x] **FS-005**: Symlink attack prevention (`Maildir/new -> /etc` must not escape storage)
- [x] **FS-006**: Symlink mailbox root attack rejected
- [x] **FS-007**: Disk full simulation fails safely without corrupting DB
- [x] **FS-008**: Read-only filesystem graceful failure
- [x] **FS-009**: Corrupted blob detection (hash mismatch)
- [x] **FS-010**: Atomic write crash recovery (no partial final file left)
- [x] **FS-011**: Garbage collection removes orphaned blobs
- [x] **FS-012**: Missing blob detection (never silently return empty email)

### 1.4 PostgreSQL Integrity (DB-001 to DB-010)
- [x] **DB-001**: Foreign key `message.mailbox_id` validation
- [x] **DB-002**: Mailbox deletion message cascade
- [x] **DB-003**: Duplicate email unique constraint
- [x] **DB-004**: Concurrent mailbox creation (10 goroutines -> exactly 1 success)
- [x] **DB-005**: Concurrent password updates preserve hash integrity
- [x] **DB-006**: Transaction rollback on partial operation failure
- [x] **DB-007**: Message/blob consistency verification
- [x] **DB-008**: Audit log transaction isolation
- [x] **DB-009**: Migration from empty database
- [x] **DB-010**: Migration from previous versions & idempotency

### 1.5 Postfix Inbound SMTP (SMTP-001 to SMTP-020)
- [x] **SMTP-001**: Valid recipient -> `250`
- [x] **SMTP-002**: Unknown recipient -> `550 User unknown`
- [x] **SMTP-003**: Unknown domain -> rejected
- [x] **SMTP-004**: Suspended mailbox -> `550 User unknown`
- [x] **SMTP-005**: Pending provisioning -> rejected
- [x] **SMTP-006**: Missing HELO -> rejected
- [x] **SMTP-007**: Invalid/malformed HELO -> rejected
- [x] **SMTP-008**: Open relay attempt (evil -> gmail) -> `554 Relay access denied`
- [x] **SMTP-009**: Local sender to external without AUTH on :25 -> rejected
- [x] **SMTP-010**: Multiple mixed recipients handled per policy
- [x] **SMTP-011**: Multiple valid recipients -> single delivery to all mailboxes
- [x] **SMTP-012**: DATA command without RCPT -> rejected
- [x] **SMTP-013**: MAIL FROM without HELO -> rejected
- [x] **SMTP-014**: Invalid MAIL FROM syntax -> rejected
- [x] **SMTP-015**: Message too large (>25MB) -> `552`
- [x] **SMTP-016**: Header injection detection
- [x] **SMTP-017**: CRLF injection prevention
- [x] **SMTP-018**: SMTP pipelining abuse prevention
- [x] **SMTP-019**: Connection timeout handling
- [x] **SMTP-020**: Connection rate limiting on burst

### 1.6 Postfix -> Maildir Delivery (DELIVERY-001 to DELIVERY-010)
- [x] **DELIVERY-001**: Accepted SMTP email written to `Maildir/new`
- [x] **DELIVERY-002**: Delivery headers (`Return-Path`, `Delivered-To`, `Received`) verified
- [x] **DELIVERY-003**: Message body byte integrity (`SHA256(original) == SHA256(stored)`)
- [x] **DELIVERY-004**: Binary attachment byte-for-byte integrity
- [x] **DELIVERY-005**: UTF-8 subject header preserved
- [x] **DELIVERY-006**: Multipart MIME structure intact
- [x] **DELIVERY-007**: Very long header folded and parsed
- [x] **DELIVERY-008**: 8-bit body handling
- [x] **DELIVERY-009**: Empty body handling
- [x] **DELIVERY-010**: Multiple attachments handling

### 1.7 IMAP (IMAP-001 to IMAP-018)
- [x] **IMAP-001**: LOGIN valid credentials -> `OK`
- [x] **IMAP-002**: LOGIN invalid password -> `NO [AUTHENTICATIONFAILED]`
- [x] **IMAP-003**: Unknown user -> `NO [AUTHENTICATIONFAILED]`
- [x] **IMAP-004**: Suspended user -> `NO [AUTHENTICATIONFAILED]`
- [x] **IMAP-005**: Pending user -> `NO [AUTHENTICATIONFAILED]`
- [x] **IMAP-006**: Case-insensitive email login
- [x] **IMAP-007**: SELECT INBOX -> mailbox state & message counts
- [x] **IMAP-008**: SEARCH ALL
- [x] **IMAP-009**: SEARCH FROM
- [x] **IMAP-010**: SEARCH SUBJECT
- [x] **IMAP-011**: FETCH headers (RFC822.HEADER)
- [x] **IMAP-012**: FETCH body (BODY[TEXT])
- [x] **IMAP-013**: FETCH attachment (BODY[2])
- [x] **IMAP-014**: STORE flags (`\Seen`, `\Flagged`, `\Deleted`)
- [x] **IMAP-015**: EXPUNGE permanently purges flagged messages
- [x] **IMAP-016**: 10 concurrent IMAP sessions on same mailbox without corruption
- [x] **IMAP-017**: Clean LOGOUT
- [x] **IMAP-018**: Abrupt TCP disconnect handled cleanly

### 1.8 SMTP Submission :587 (SUB-001 to SUB-015)
- [x] **SUB-001**: AUTH before STARTTLS -> `530 5.7.0 Must issue a STARTTLS command first`
- [x] **SUB-002**: STARTTLS negotiation -> `220 2.0.0 Ready to start TLS`
- [x] **SUB-003**: AUTH correct password -> `235 2.7.0 Authentication successful`
- [x] **SUB-004**: AUTH wrong password -> `535 5.7.8 Authentication failed`
- [x] **SUB-005**: AUTH unknown account -> `535 Authentication failed`
- [x] **SUB-006**: AUTH suspended account -> `535 Authentication failed`
- [x] **SUB-007**: Outbound relay allowed after valid authentication
- [x] **SUB-008**: Outbound relay without authentication rejected
- [x] **SUB-009**: Sender anti-spoofing (`AUTH ajar@` -> `MAIL FROM:<ceo@>` rejected)
- [x] **SUB-010**: Authorized alias (`AUTH ajar` -> `MAIL FROM:<support@>` accepted)
- [x] **SUB-011**: Unauthorized alias rejected
- [x] **SUB-012**: Password change takes effect immediately on :587 without restart
- [x] **SUB-013**: Messages per minute rate limiting
- [x] **SUB-014**: Recipients per hour rate limiting
- [x] **SUB-015**: Daily quota enforcement

### 1.9 TLS & STARTTLS (TLS-001 to TLS-013)
- [x] **TLS-001**: TLS 1.2 handshake succeeds
- [x] **TLS-002**: TLS 1.3 handshake succeeds
- [x] **TLS-003**: Legacy TLS 1.0 blocked
- [x] **TLS-004**: Legacy TLS 1.1 blocked
- [x] **TLS-005**: Hostname mismatch detected by TLS Doctor
- [x] **TLS-006**: Expired certificate detected by TLS Doctor
- [x] **TLS-007**: Certificate and private key mismatch rejected on install
- [x] **TLS-008**: Corrupted PEM rejected on install
- [x] **TLS-009**: Private key permissions enforced `0600`
- [x] **TLS-010**: Atomic certificate replacement (active cert preserved on invalid update)
- [x] **TLS-011**: STARTTLS downgrade attack rejected
- [x] **TLS-012**: Implicit IMAPS (:993) TLS handshake
- [x] **TLS-013**: Plaintext IMAP login on :143 rejected with `PRIVACYREQUIRED`

### 1.10 DKIM (DKIM-001 to DKIM-010)
- [x] **DKIM-001**: RSA-2048 key generation
- [x] **DKIM-002**: Private key permission `0600`, directory `0750`
- [x] **DKIM-003**: Public key matches private key modulus
- [x] **DKIM-004**: DNS TXT record verification succeeds
- [x] **DKIM-005**: Wrong DNS public key detected as verification failure
- [x] **DKIM-006**: Activate selector for live signing
- [x] **DKIM-007**: Outbound signing via OpenDKIM produces valid `DKIM-Signature` (`d=`, `s=`)
- [x] **DKIM-008**: Message body/header tampering causes DKIM verification failure
- [x] **DKIM-009**: Selector rotation (both old & new selectors coexist and verify)
- [x] **DKIM-010**: Revoke DKIM selector

### 1.11 SPF (SPF-001 to SPF-010)
- [x] **SPF-001**: Valid SPF syntax validation
- [x] **SPF-002**: SPF `pass` evaluation
- [x] **SPF-003**: SPF `fail` evaluation (`-all`)
- [x] **SPF-004**: SPF `softfail` evaluation (`~all`)
- [x] **SPF-005**: SPF `neutral` evaluation (`?all`)
- [x] **SPF-006**: No SPF record (`none`)
- [x] **SPF-007**: Malformed SPF record -> `PermError`
- [x] **SPF-008**: Multiple SPF TXT records -> `PermError`
- [x] **SPF-009**: DNS temporary failure -> `TempError`
- [x] **SPF-010**: SPF 10-lookup limit enforcement

### 1.12 DMARC (DMARC-001 to DMARC-011)
- [x] **DMARC-001**: SPF aligned only -> DMARC `pass`
- [x] **DMARC-002**: DKIM aligned only -> DMARC `pass`
- [x] **DMARC-003**: Both SPF & DKIM fail -> DMARC `fail`
- [x] **DMARC-004**: SPF pass with unaligned domain -> DMARC fails SPF alignment
- [x] **DMARC-005**: DKIM pass with unaligned domain -> DMARC fails DKIM alignment
- [x] **DMARC-006**: Policy `p=none` -> deliver and mark
- [x] **DMARC-007**: Policy `p=quarantine` -> Junk/Quarantine routing
- [x] **DMARC-008**: Policy `p=reject` -> SMTP 550 reject
- [x] **DMARC-009**: Strict identifier alignment (`adkim=s`, `aspf=s`)
- [x] **DMARC-010**: Relaxed identifier alignment (`adkim=r`, `aspf=r`)
- [x] **DMARC-011**: Subdomain policy inheritance (`sp=reject`)

### 1.13 Anti-Spam / Antivirus (AV-001 to AV-008)
- [x] **AV-001**: Clean message delivery
- [x] **AV-002**: EICAR standard test signature -> `malware_detected` rejection
- [x] **AV-003**: ClamAV unavailable fail-open/fail-closed deterministic behavior
- [x] **AV-004**: Rspamd clean message evaluation
- [x] **AV-005**: High spam score (>6.0) -> Junk/quarantine headers
- [x] **AV-006**: Rspamd unavailable fail-open deterministic behavior
- [x] **AV-007**: Oversized message/attachment (>25MB) rejected
- [x] **AV-008**: Nested MIME attachment parsing

### 1.14 Security & Hardening (SEC-001 to SEC-016)
- [x] **SEC-001**: SQL injection resilience on domain/email/alias/selector/messageID
- [x] **SEC-002**: Path traversal protection on all filesystem inputs
- [x] **SEC-003**: Symlink traversal protection
- [x] **SEC-004**: Shell command injection prevention on postqueue/postcat/postsuper
- [x] **SEC-005**: PostgreSQL least-privilege role verification
- [x] **SEC-006**: Dovecot DB role cannot `INSERT`, `UPDATE`, or `DELETE`
- [x] **SEC-007**: Postfix DB role cannot modify DB tables
- [x] **SEC-008**: DKIM private keys never leaked in logs
- [x] **SEC-009**: TLS private keys never leaked in logs
- [x] **SEC-010**: Passwords never leaked in logs
- [x] **SEC-011**: SMTP AUTH credentials never leaked in logs
- [x] **SEC-012**: Backup passphrase never leaked in logs
- [x] **SEC-013**: CLI `--password-stdin` support to avoid process list exposure
- [x] **SEC-014**: User enumeration prevention (identical 550 response for unknown and suspended)
- [x] **SEC-015**: Authentication timing attack resilience (constant-time Argon2id comparison)
- [x] **SEC-016**: Brute-force auth sliding window rate limiter

### 1.15 Storage Quota (QUOTA-001 to QUOTA-006)
- [x] **QUOTA-001**: Mailbox usage 0% -> `OK`
- [x] **QUOTA-002**: Mailbox usage 80% -> `WARNING`
- [x] **QUOTA-003**: Mailbox usage 90% -> `CRITICAL`
- [x] **QUOTA-004**: Mailbox usage 100% -> `552 5.2.2 Mailbox is full`
- [x] **QUOTA-005**: Maildir disk reconciler syncs counter to DB
- [x] **QUOTA-006**: Concurrent deliveries around quota boundary handled safely

### 1.16 Postfix Queue Management (QUEUE-001 to QUEUE-010)
- [x] **QUEUE-001**: Active queue inspection
- [x] **QUEUE-002**: Deferred message inspection with reason
- [x] **QUEUE-003**: Retry deferred queue (`postsuper -r`)
- [x] **QUEUE-004**: Delete queue message (`postsuper -d`)
- [x] **QUEUE-005**: Hold queue message (`postsuper -h`)
- [x] **QUEUE-006**: Release held message (`postsuper -H`)
- [x] **QUEUE-007**: Flush queue (`postqueue -f`)
- [x] **QUEUE-008**: Corrupt queue entry detected by Queue Doctor
- [x] **QUEUE-009**: Unknown queue ID safe error handling
- [x] **QUEUE-010**: Queue command injection resistance

### 1.17 Bounce & DSN Processing (BOUNCE-001 to BOUNCE-008)
- [x] **BOUNCE-001**: 5.1.1 -> `PERMANENT`, `RECIPIENT_UNKNOWN`
- [x] **BOUNCE-002**: 5.2.2 -> `PERMANENT`, `MAILBOX_FULL`
- [x] **BOUNCE-003**: 5.7.1 -> `PERMANENT`, `POLICY_REJECTION`
- [x] **BOUNCE-004**: 4.7.1 -> `TEMPORARY`, `TEMPORARY_FAILURE`
- [x] **BOUNCE-005**: 4.4.1 -> `TEMPORARY`, `CONNECTION_FAILURE`
- [x] **BOUNCE-006**: Malformed DSN parsed without panic
- [x] **BOUNCE-007**: Multipart DSN parsing
- [x] **BOUNCE-008**: Unknown enhanced status code fallback

### 1.18 Audit & Message Events (AUDIT-001 to AUDIT-010)
- [x] **AUDIT-001**: Mailbox creation audit log
- [x] **AUDIT-002**: Password change audit log
- [x] **AUDIT-003**: Mailbox suspension audit log
- [x] **AUDIT-004**: Mailbox deletion audit log
- [x] **AUDIT-005**: DKIM key activation audit log
- [x] **AUDIT-006**: DKIM key revocation audit log
- [x] **AUDIT-007**: Backup creation audit log
- [x] **AUDIT-008**: Backup restoration audit log
- [x] **AUDIT-009**: Queue message deletion audit log
- [x] **AUDIT-010**: Failed admin operations logged with actor/target without leaking secrets

### 1.19 Observability (OBS-001 to OBS-011)
- [x] **OBS-001**: Every transaction mapped to correlation / Message ID & Queue ID
- [x] **OBS-002**: Message trace: `received` -> `authenticated` -> `queued` -> `delivery_attempt` -> `delivered`
- [x] **OBS-003**: Deferred trace: `queued` -> `delivery_attempt` -> `deferred`
- [x] **OBS-004**: Bounce trace: `queued` -> `delivery_attempt` -> `bounced`
- [x] **OBS-005**: Spam trace: `received` -> `spam_detected` -> `quarantined`
- [x] **OBS-006**: Malware trace: `received` -> `malware_detected`
- [x] **OBS-007**: Prometheus `/metrics` increments correctly
- [x] **OBS-008**: Metrics do not leak email addresses, passwords, or message contents
- [x] **OBS-009**: `/health/live` returns OK even if DB is down
- [x] **OBS-010**: `/health/ready` returns DOWN when DB is down
- [x] **OBS-011**: `/health/deep` detects storage / queue failures

### 1.20 Backup & Disaster Recovery (BACKUP-001 to BACKUP-013)
- [x] **BACKUP-001**: Create AES-256-GCM encrypted backup archive
- [x] **BACKUP-002**: Wrong passphrase rejected without extracting
- [x] **BACKUP-003**: Corrupt ciphertext rejected
- [x] **BACKUP-004**: Modified manifest rejected
- [x] **BACKUP-005**: Truncated backup rejected
- [x] **BACKUP-006**: Restore into empty disposable environment
- [x] **BACKUP-007**: PostgreSQL schema & tables restored
- [x] **BACKUP-008**: Maildir restored with intact message files
- [x] **BACKUP-009**: DKIM private keys restored with `0600` permissions
- [x] **BACKUP-010**: TLS certificates restored
- [x] **BACKUP-011**: Subsystem configurations restored
- [x] **BACKUP-012**: Post-restore live SMTP, IMAP, AUTH, and DKIM verification
- [x] **BACKUP-013**: Full disaster simulation (destroy entire environment -> restore -> System Doctor HEALTHY)

### 1.21 Crash & Recovery (RECOVERY-001 to RECOVERY-011)
- [x] **RECOVERY-001**: Process termination during mailbox provisioning recovered cleanly
- [x] **RECOVERY-002**: Postfix restart preserves mail queue
- [x] **RECOVERY-003**: Dovecot restart preserves Maildir
- [x] **RECOVERY-004**: PostgreSQL unavailable causes fail-safe SMTP rejection (no open relay / ghost deliver)
- [x] **RECOVERY-005**: PostgreSQL reconnection restores service automatically
- [x] **RECOVERY-006**: Rspamd unavailable fail-open deterministic recovery
- [x] **RECOVERY-007**: ClamAV unavailable fail-closed / fail-open deterministic recovery
- [x] **RECOVERY-008**: OpenDKIM unavailable fail-safe recovery
- [x] **RECOVERY-009**: DNS unavailable timeout handling
- [x] **RECOVERY-010**: Storage filesystem full/readonly graceful recovery
- [x] **RECOVERY-011**: Full stack restart consistency (`docker compose down` -> `up`)

### 1.22 Concurrency (CONC-001 to CONC-010)
- [x] **CONC-001**: 100 concurrent SMTP connections
- [x] **CONC-002**: 100 concurrent IMAP logins
- [x] **CONC-003**: 100 concurrent mailbox lookups
- [x] **CONC-004**: Concurrent mailbox creation for the same email address
- [x] **CONC-005**: Concurrent password update and login attempt
- [x] **CONC-006**: Concurrent deliveries to the same mailbox
- [x] **CONC-007**: Concurrent quota reconciliation and message delivery
- [x] **CONC-008**: Concurrent queue management operations
- [x] **CONC-009**: Concurrent message deletion and IMAP fetch
- [x] **CONC-010**: `go test -race ./...` zero race conditions detected

### 1.23 Migration & Schema Upgrade (MIG-001 to MIG-007)
- [x] **MIG-001**: Empty database to latest version (000001 -> 000010)
- [x] **MIG-002**: Step-by-step sequential migration execution
- [x] **MIG-003**: Migration rerun idempotency
- [x] **MIG-004**: Migration failure rollback testing
- [x] **MIG-005**: Full migration downgrade execution (10 -> 1)
- [x] **MIG-006**: Schema table & column integrity verification
- [x] **MIG-007**: Existing production data retained across migrations

### 1.24 Fuzz Testing (FUZZ-001 to FUZZ-010)
- [x] **FUZZ-001**: Fuzz Email Address Parser
- [x] **FUZZ-002**: Fuzz Domain Name Parser
- [x] **FUZZ-003**: Fuzz DKIM Selector & Record Parser
- [x] **FUZZ-004**: Fuzz SMTP Headers & CRLF Parser
- [x] **FUZZ-005**: Fuzz MIME Multipart Body Parser
- [x] **FUZZ-006**: Fuzz SPF Policy Parser
- [x] **FUZZ-007**: Fuzz DMARC Policy Parser
- [x] **FUZZ-008**: Fuzz DSN Delivery Status Notification Parser
- [x] **FUZZ-009**: Fuzz Postfix Queue Output Parser
- [x] **FUZZ-010**: Fuzz Backup Manifest Parser

### 1.25 Resource Exhaustion (RES-001 to RES-010)
- [x] **RES-001**: Huge SMTP command buffer protection
- [x] **RES-002**: Huge header line limit protection
- [x] **RES-003**: Huge subject header protection
- [x] **RES-004**: Huge recipient list protection
- [x] **RES-005**: Deep MIME nesting protection (zip bomb / recursion)
- [x] **RES-006**: Huge attachment stream parsing
- [x] **RES-007**: High connection concurrency memory bounding
- [x] **RES-008**: High auth failure memory bounding
- [x] **RES-009**: Large queue parsing memory bounding
- [x] **RES-010**: Large Maildir scanning performance bounding

### 1.26 Protocol Compliance (PROTO-001 to PROTO-010)
- [x] **PROTO-001**: SMTP command set: EHLO, HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT
- [x] **PROTO-002**: STARTTLS state machine enforcement
- [x] **PROTO-003**: SMTP RSET resets transaction state cleanly
- [x] **PROTO-004**: Multiple consecutive MAIL FROM transactions in single connection
- [x] **PROTO-005**: Multiple RCPT commands in single transaction
- [x] **PROTO-006**: SMTP dot-stuffing and dot-unstuffing (`.` and `..`)
- [x] **PROTO-007**: 8BITMIME body extension
- [x] **PROTO-008**: SMTP SIZE limit negotiation and enforcement
- [x] **PROTO-009**: IMAP 4-state machine (NONAUTHENTICATED, AUTHENTICATED, SELECTED, LOGOUT)
- [x] **PROTO-010**: Invalid commands in each IMAP state return protocol error without crashing

### 1.27 Full E2E Golden Scenarios (GOLDEN-001 to GOLDEN-010)
- [x] **GOLDEN-001**: Inbound E2E (Internet -> Postfix :25 -> lookup -> SPF -> DKIM -> DMARC -> Rspamd -> ClamAV -> Maildir -> Dovecot -> IMAP)
- [x] **GOLDEN-002**: Outbound E2E (Submission :587 STARTTLS -> Dovecot SASL AUTH -> Sender Auth -> Postfix -> OpenDKIM Milter Signing -> DKIM-Signature)
- [x] **GOLDEN-003**: Alias delivery (`support@` -> `ajar@` -> Maildir -> IMAP)
- [x] **GOLDEN-004**: Invalid recipient (`ghost@` -> `550`, zero Maildir created)
- [x] **GOLDEN-005**: Spam delivery (High spam score -> Junk/quarantine headers)
- [x] **GOLDEN-006**: Malware rejection (EICAR signature -> rejected/quarantined)
- [x] **GOLDEN-007**: DMARC reject (SPF fail + DKIM fail + `p=reject` -> SMTP 550 reject)
- [x] **GOLDEN-008**: Storage Quota (100% full -> SMTP `552 5.2.2 Mailbox full`)
- [x] **GOLDEN-009**: Password rotation (old password fails, new password works on IMAP & :587 instantly without restart)
- [x] **GOLDEN-010**: Disaster Recovery Boss Fight (Destroy DB, Maildir, DKIM, TLS, Configs -> Restore from encrypted backup -> System Doctor HEALTHY -> Live SMTP, IMAP, AUTH, DKIM signing, Alias verified)

---

## 2. Directory Structure for Test Suites

```text
tests/
├── protocol/
│   ├── smtp_protocol_test.go
│   ├── submission_protocol_test.go
│   └── imap_protocol_test.go
├── security/
│   └── security_test.go
├── recovery/
│   └── recovery_test.go
├── fuzz/
│   └── fuzz_test.go
├── concurrency/
│   └── concurrency_test.go
└── e2e/
    └── golden_scenarios_test.go
```
