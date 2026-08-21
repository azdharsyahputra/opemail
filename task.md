# MailOpen W2 — Production GA Hardening & Verification Plan

## 1. Upgrade & Migration Integrity (UPGRADE-001 to UPGRADE-003)
- [x] **UPGRADE-001**: Upgrade from previous state preserving domains, mailboxes, passwords, aliases, Maildir, DKIM metadata/keys, TLS certs, quota, audit logs, and message contents
- [x] **UPGRADE-002**: Migration mid-stream failure rollback (transactional atomicity)
- [x] **UPGRADE-003**: Incompatible downgrade prevention

## 2. Fresh Installation & Bootstrap (INSTALL-001)
- [x] **INSTALL-001**: Clean installation bootstrap -> `mailopen system doctor` HEALTHY

## 3. Uninstall & Purge Safety (PURGE-001)
- [x] **PURGE-001**: Clean uninstall preserving user data; explicit confirmation required for destructive `--all-data` purge

## 4. Idempotency Matrix (IDEMP-001 to IDEMP-008)
- [x] **IDEMP-001**: Domain create idempotency
- [x] **IDEMP-002**: Mailbox create idempotency
- [x] **IDEMP-003**: Alias create idempotency
- [x] **IDEMP-004**: TLS certificate install idempotency
- [x] **IDEMP-005**: DKIM key generation idempotency
- [x] **IDEMP-006**: DKIM key activation idempotency
- [x] **IDEMP-007**: Config generation idempotency (SHA-256 identical)
- [x] **IDEMP-008**: Provisioning workflow idempotency

## 5. Provisioning State Machine & Rollback (PROVISION-001 to PROVISION-006)
- [x] **PROVISION-001**: DB failure state handling
- [x] **PROVISION-002**: Filesystem failure state handling
- [x] **PROVISION-003**: Permission failure state handling
- [x] **PROVISION-004**: Config generation failure state handling
- [x] **PROVISION-005**: Service reload failure state handling
- [x] **PROVISION-006**: Automatic and manual retry provisioning mechanism

## 6. Production Disaster Recovery & RPO/RTO (DR-001 to DR-003, BACKUP-014 to BACKUP-016)
- [x] **BACKUP-014**: Snapshot consistency during active incoming mail flow
- [x] **BACKUP-015**: Postfix queue state handling during backup
- [x] **BACKUP-016**: Cross-machine restore into clean environment
- [x] **DR-001**: RPO measured under 15 minutes ($\text{RPO} \le 15\text{m}$)
- [x] **DR-002**: RTO measured under 30 minutes ($\text{RTO} \le 30\text{m}$)
- [x] **DR-003**: Comprehensive DR breakdown metrics documented

## 7. Real Inbound & Outbound Deliverability (OUTBOUND-001..003, INBOUND-001..003)
- [x] **OUTBOUND-001**: Outbound deliverability contract (SPF, DKIM, DMARC, PTR, TLS, Authentication-Results)
- [x] **INBOUND-001**: Inbound deliverability contract (SPF, DKIM, DMARC validation and header tagging)

## 8. Deep Security & Abuse Protections
- [x] **ABUSE-001..005**: 1000 connections/auth flood, password spraying, spam burst rate limiting
- [x] **HEADER-001..004**: System header forgery prevention (`Authentication-Results`, `Received`, `Return-Path`, `Delivered-To`, `DKIM-Signature`)
- [x] **MIME-001..005**: Nested multipart, 1000 MIME parts, large header, invalid boundary abuse
- [x] **ATTACH-001..004**: 25MB boundary, nested archive, double extension, EICAR protection
- [x] **QUEUE-001..004**: 10k messages queue torture, zero lost messages, no duplicate deliveries
- [x] **QUOTA-001..004**: Concurrent quota race protection under boundary load
- [x] **DBSEC-001**: PostgreSQL role boundary (SELECT-only for Postfix and Dovecot)

## 9. Config Drift & Deterministic Generation (GEN-001 to GEN-003)
- [x] **GEN-001**: Config generator determinism (SHA256 identical outputs)
- [x] **GEN-002**: Config drift detection

## 10. CLI Contract & Standardized Exit Codes
- [x] **CLI-001**: Standard exit codes (0=OK, 1=Generic, 2=InvalidArgument, 3=ConfigError, 4=DependencyDown, 5=AuthFail, 6=AuthzFail, 7=NotFound)
- [x] **CLI-002**: Non-interactive `--password-stdin` compliance across all commands

## 11. Performance Baseline Benchmark & Soak Test
- [x] **PERF-001**: Latency baseline (p50, p95, p99 for SMTP Auth, IMAP Login, Mailbox Lookup)
- [x] **SOAK-001**: Extended stability soak run (memory, goroutines, FD bounding)

## 12. Runbooks, SBOM, Licenses & Security Disclosure
- [x] **DOC-001**: Complete `docs/operations/` runbooks (installation, upgrade, backup-restore, disaster-recovery, queue, troubleshooting, security, monitoring, incident-response)
- [x] **DOC-002**: `SECURITY.md` vulnerability reporting policy
- [x] **DOC-003**: `THIRD_PARTY_LICENSES.md` compliance manifest
- [x] **DOC-004**: `SBOM.json` Software Bill of Materials

## 13. Release Artifacts & Master Verification
- [x] **REL-001**: Build Linux amd64 and arm64 release binaries with `dist/SHA256SUMS`
- [x] **REL-002**: Master `./scripts/prove-w2.sh` execution verifying all GA criteria
